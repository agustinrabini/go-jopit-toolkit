/**
* @author mnunez
 */

package handlers

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jopitnow/go-jopit-toolkit/goauth"
	"github.com/jopitnow/go-jopit-toolkit/goutils"
	"github.com/jopitnow/go-jopit-toolkit/goutils/apierrors"
	"github.com/jopitnow/go-jopit-toolkit/goutils/logger"
	json "github.com/json-iterator/go"
)

var (
	jsonpContentType      = []string{"text/javascript;charset=UTF-8"}
	publicMessageError, _ = json.Marshal(apierrors.NewApiError("Oops! Something went wrong...", "TK_02", http.StatusInternalServerError, nil))
)

const (
	ginMiddlewareErrorContextKey = "_jopitMiddlewareError"
)

type customWritter struct {
	// gin context
	context *gin.Context
	// real ResponseWriter to flush to
	response gin.ResponseWriter
	// response content body buffer. It is used only if attr filter, jsonp filter or an error is present
	body *bytes.Buffer
	// bytes that have been written
	written int

	logErrors bool
}

// Because we are using a custom writer to buffer the body in memory, we need to
// make methods that force writing to the socket no-ops.
func (w *customWritter) Flush()          {}
func (w *customWritter) WriteHeaderNow() {}

func (w *customWritter) Pusher() (pusher http.Pusher) {
	return w.response.Pusher()
}

// middleware that intercepts the requests, check if attributes and jsonp filters are requested and apply them
// it also intercepts internal server errors, log the information and notice the information to newrelic in a detailed mode.
// In error handling logs the URI is included, and it may contains private data like tokens in params or query params.
// Because of that, error handling logs will be omitted if logErrors is false.
func CommonAPiFilter(logErrors bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		var wb *customWritter

		// detects if we are using a gin response writer and wrap it. if not middleware is avoided
		if w, ok := c.Writer.(gin.ResponseWriter); ok {
			// custom writer that will wrap the real one. It uses a buffer to store response body and change it before flush to the real writer
			wb = &customWritter{context: c, response: w, body: &bytes.Buffer{}, logErrors: logErrors}
			c.Writer = wb
			c.Next()
		} else {
			c.Next()
			return
		}

		data := wb.body.Bytes()
		if len(data) > 0 {
			wb.body.Reset()
			if strings.Index(wb.Header().Get("Content-Type"), "/json") >= 0 {
				//2xx response and attributes filter
				if wb.Status()/100 == 2 {
					if attributes := c.Query("attributes"); len(attributes) > 0 {
						var err apierrors.ApiError
						data, err = applyAttributesFilter(attributes, data)
						if err != nil {
							wb.response.WriteHeader(err.Status())
							data, _ = json.Marshal(err)
						}
					}
				}

				if jsonpFilter := c.Query("callback"); len(jsonpFilter) > 0 {
					wb.Header()["Content-Type"] = jsonpContentType
					headers, err := goutils.ToJSONString(wb.Header())
					if err != nil {
						headers = "{}"
					}
					data = []byte(fmt.Sprintf("%s([%d,%s,%s]);", jsonpFilter, wb.response.Status(), headers, string(data)))
				}
			}
			wb.written = len(data)
			wb.response.Write(data)
		}
		wb.Header().Set("Content-Length", strconv.Itoa(wb.written))
	}
}

func (w *customWritter) Header() http.Header {
	return w.response.Header() // use the actual response header
}

// SetRequestError sets the given error into the provided gin context
func SetRequestError(c *gin.Context, err error) {
	c.Set(ginMiddlewareErrorContextKey, err)
}

// Retrieves the internal error from the gin context
func errorFromGinContext(c *gin.Context) error {
	ctxErr, found := c.Get(ginMiddlewareErrorContextKey)
	if !found {
		return nil
	}

	val, _ := ctxErr.(error)
	return val
}

func (w *customWritter) Write(buf []byte) (int, error) {
	// Avoiding buffer when filtering is not needed (not a 5xx and jsonp or attributes not required)
	if w.Status() >= http.StatusInternalServerError {
		buf = handleServerError(w.context, buf, w.Status(), w.logErrors)
	}

	size, err := w.body.Write(buf)
	w.written += size
	return size, err
}

func (w *customWritter) WriteString(s string) (int, error) {
	return w.Write([]byte(s))
}

func (w *customWritter) Written() bool {
	// Gin resets its responseWriter using -1 as not written on ServeHTTP calls
	// Is is not a struct default but a writer default for the request life cycle
	// TODO: Check if this logic applies here
	return w.body.Len() != -1
}

func (w *customWritter) WriteHeader(status int) {
	w.response.WriteHeader(status)
}

func (w *customWritter) Status() int {
	return w.response.Status()
}

func (w *customWritter) Size() int {
	return w.written
}

func (w *customWritter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.response.(http.Hijacker).Hijack()
}

func (w *customWritter) CloseNotify() <-chan bool {
	return w.response.(http.CloseNotifier).CloseNotify()
}

// Errors handling
func handleServerError(c *gin.Context, data []byte, status int, logError bool) []byte {
	uri := c.Request.RequestURI
	dataErr := retrieveAndNoticeMiddlewareError(c, data, status)

	if logError {
		logger.Errorf("Internal Server Error executing %s", dataErr, uri)
	}

	if goauth.IsPublic(c.Request) {
		return publicMessageError
	}

	data, _ = json.Marshal(dataErr)
	return data
}

// Retrieves the propagated error and notices the internal error from the different available
// middleware sources in order of availability: context -> middleware
func retrieveAndNoticeMiddlewareError(c *gin.Context, data []byte, status int) apierrors.ApiError {

	ctxErr := errorFromGinContext(c)
	if ctxErr != nil {
		return apierrors.NewApiError(
			ctxErr.Error(),
			"TK_03",
			status,
			apierrors.CauseList{
				"Error from context middleware",
			},
		)
	}

	message := "An error occurred"
	if len(data) > 0 {
		message = string(data)
	}

	return apierrors.NewApiError(
		message,
		"TK_04",
		status,
		nil,
	)

}

//Attributes filter

/*
Receives a list of attributes and remove unwanted fields from json
*/
func applyAttributesFilter(attributes string, data []byte) ([]byte, apierrors.ApiError) {
	var result interface{}
	attributesTree := parseAttributes(attributes)
	if string(data[0]) == "[" {
		aux := make([]interface{}, 0)
		err := json.Unmarshal(data, &aux)
		if err != nil {
			return nil, apierrors.NewApiError("Error unmarshalling filterable json content", "TK_05", http.StatusInternalServerError, apierrors.CauseList{err})
		}
		filterSlice(aux, attributesTree)
		result = aux
	} else {
		aux := make(map[string]interface{})
		err := json.Unmarshal(data, &aux)
		if err != nil {
			return nil, apierrors.NewApiError("Error unmarshalling filterable json content", "TK_05", http.StatusInternalServerError, apierrors.CauseList{err})
		}
		filterMap(aux, attributesTree)
		result = aux
	}

	res, err := json.Marshal(result)
	if err != nil {
		return nil, apierrors.NewApiError("Error marshalling filterable json content", "TK_05", http.StatusInternalServerError, apierrors.CauseList{err})
	}
	return res, nil
}

/*
Returns a map schema of string attributes filter representation
*/
func parseAttributes(query string) map[string]interface{} {
	fields := strings.Split(query, ",")
	trie := make(map[string]interface{})
	for i := 0; i < len(fields); i++ {
		subFields := strings.Split(fields[i], ".")
		currentNode := trie
		lastPos := len(subFields) - 1
		for j := 0; j < lastPos; j++ {
			nextNode, nodeExists := currentNode[subFields[j]].(map[string]interface{})
			if !nodeExists {
				nextNode = make(map[string]interface{})
				currentNode[subFields[j]] = nextNode
			}
			currentNode = nextNode
		}
		if _, attributeIsInTrie := currentNode[subFields[lastPos]]; !attributeIsInTrie {
			currentNode[subFields[lastPos]] = false
		}
	}
	return trie
}

/*
Iterate each key value pair and remove not required attributes
*/
func filterMap(toFilter map[string]interface{}, attributes map[string]interface{}) {
	for key, val := range toFilter {
		if subFilter, ok := attributes[key]; ok {
			if _, ok := subFilter.(bool); !ok {
				dataValue := reflect.ValueOf(val)
				if dataValue.Kind() == reflect.Slice {
					filterSlice(val.([]interface{}), subFilter.(map[string]interface{}))
				} else if dataValue.Kind() == reflect.Map {
					filterMap(val.(map[string]interface{}), subFilter.(map[string]interface{}))
				}
			} else {
				attributes[key] = true
			}
		} else {
			delete(toFilter, key)
		}
	}
}

/*
Iterate each element and remove not requiered attributes
It will filter leaf nodes that contain maps, otherwise they will be skipped
*/
func filterSlice(value []interface{}, attributes map[string]interface{}) {
	for i := 0; i < len(value); i++ {
		dataValue := reflect.ValueOf(value[i])
		if dataValue.Kind() == reflect.Slice {
			filterSlice(value[i].([]interface{}), attributes)
		} else if dataValue.Kind() == reflect.Map {
			filterMap(value[i].(map[string]interface{}), attributes)
		}
	}
}
