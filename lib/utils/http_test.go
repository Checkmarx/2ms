package utils

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

type MockAuthorization struct {
	header string
}

func (m *MockAuthorization) GetAuthorizationHeader() string {
	return m.header
}

func TestHttpRequest(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		url           string
		statusCode    int
		authorization string
		retry         RetrySettings
		responseBody  string
		bodyError     bool
		expectedError error
	}{
		{
			name:         "Successful request",
			method:       "GET",
			statusCode:   http.StatusOK,
			responseBody: "Success",
		},
		{
			name:          "Request with authorization",
			method:        "GET",
			statusCode:    http.StatusOK,
			authorization: "Bearer token123",
			responseBody:  "Authorized",
		},
		{
			name:          "Retry on failure",
			method:        "GET",
			statusCode:    http.StatusInternalServerError,
			retry:         RetrySettings{MaxRetries: 1, ErrorCodes: []int{http.StatusInternalServerError}},
			expectedError: errors.New("error calling http url"),
		},
		{
			name:          "Client error (no retry)",
			method:        "GET",
			statusCode:    http.StatusBadRequest,
			expectedError: errors.New("error calling http url"),
		},
		{
			name:          "Error creating request",
			method:        "GET",
			url:           "::://invalid-url",
			expectedError: errors.New("unexpected error creating an http request"),
		},
		{
			name:          "Error sending request",
			method:        "GET",
			url:           "http://localhost:9999",
			expectedError: errors.New("unable to send http request"),
		},
		{
			name:          "Error reading response body",
			method:        "GET",
			statusCode:    http.StatusOK,
			bodyError:     true,
			expectedError: errors.New("unexpected error reading http response body"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var server *httptest.Server
			if test.url == "" {
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if test.authorization != "" {
						assert.Equal(t, test.authorization, r.Header.Get("Authorization"), "Authorization header mismatch")
					}
					w.WriteHeader(test.statusCode)
					if test.bodyError {
						_, err := w.Write([]byte("corrupt data"))
						assert.NoError(t, err)
						w.(http.Flusher).Flush()
						conn, _, _ := w.(http.Hijacker).Hijack()
						err = conn.Close()
						assert.NoError(t, err)
					} else {
						_, _ = w.Write([]byte(test.responseBody))
					}
				}))
				test.url = server.URL
				defer server.Close()
			}

			mockAuth := &MockAuthorization{header: test.authorization}
			body, response, err := HttpRequest(test.method, test.url, mockAuth, test.retry)

			if test.expectedError != nil {
				assert.Error(t, err, "Expected an error but got none")
				assert.Contains(t, err.Error(), test.expectedError.Error(), "Unexpected error message")
			} else {
				assert.NoError(t, err, "Unexpected error occurred")
				assert.Equal(t, test.statusCode, response.StatusCode, "Unexpected status code")
				assert.Equal(t, test.responseBody, string(body), "Unexpected response body")
			}
		})
	}
}
