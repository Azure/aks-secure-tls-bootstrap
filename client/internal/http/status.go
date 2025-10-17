package http

import "net/http"

func IsRetryableHTTPStatusCode(code int) bool {
	if code == http.StatusTooManyRequests || code == http.StatusConflict {
		return true
	}
	return code >= http.StatusInternalServerError && code != http.StatusNotImplemented
}
