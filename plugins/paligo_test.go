package plugins

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
	"net/http"
	"testing"
	"time"
)

func TestReserveRateLimit(t *testing.T) {
	tests := []struct {
		name           string
		response       *http.Response
		limiter        *rate.Limiter
		inputErr       error
		expectedErrSub string
		expectedBurst  int
		minSleep       int64
		maxSleep       int64
	}{
		{
			name: "Non-429 status returns input error",
			response: &http.Response{
				StatusCode: 200,
			},
			limiter:        rate.NewLimiter(1, 10),
			inputErr:       fmt.Errorf("non rate limit error"),
			expectedErrSub: "non rate limit error",
			expectedBurst:  10,
			minSleep:       0,
			maxSleep:       0,
		},
		{
			name: "429 status missing Retry-After header returns error",
			response: &http.Response{
				StatusCode: 429,
				Header:     http.Header{},
			},
			limiter:        rate.NewLimiter(1, 10),
			inputErr:       nil,
			expectedErrSub: "Retry-After header not found",
			expectedBurst:  10,
			minSleep:       0,
			maxSleep:       0,
		},
		{
			name: "429 status with invalid Retry-After header returns error",
			response: &http.Response{
				StatusCode: 429,
				Header: http.Header{
					"Retry-After": []string{"abc"},
				},
			},
			limiter:        rate.NewLimiter(1, 10),
			inputErr:       nil,
			expectedErrSub: "error parsing Retry-After header",
			expectedBurst:  10,
			minSleep:       0,
			maxSleep:       0,
		},
		{
			name: "429 status with valid Retry-After header (0) returns nil and sets burst to 1 with minimal sleep",
			response: &http.Response{
				StatusCode: 429,
				Header: http.Header{
					"Retry-After": []string{"0"},
				},
			},
			limiter:        rate.NewLimiter(1, 10),
			inputErr:       nil,
			expectedErrSub: "",
			expectedBurst:  1,
			minSleep:       0,
			maxSleep:       50,
		},
		{
			name: "429 status with valid Retry-After header (1) returns nil and sets burst to 1 with ~1 sec sleep",
			response: &http.Response{
				StatusCode: 429,
				Header: http.Header{
					"Retry-After": []string{"1"},
				},
			},
			limiter:        rate.NewLimiter(1, 10),
			inputErr:       nil,
			expectedErrSub: "",
			expectedBurst:  1,
			minSleep:       1000,
			maxSleep:       1050,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			err := reserveRateLimit(tc.response, tc.limiter, tc.inputErr)
			duration := time.Since(start).Milliseconds()

			if tc.expectedErrSub != "" {
				assert.Error(t, err, "expected an error")
				assert.Contains(t, err.Error(), tc.expectedErrSub, "error message mismatch")
			} else {
				assert.NoError(t, err, "expected no error")
				if tc.maxSleep > 0 {
					assert.GreaterOrEqual(t, duration, tc.minSleep, "expected sleep of at least %d ms", tc.minSleep)
					assert.Less(t, duration, tc.maxSleep, "expected sleep of less than %d ms", tc.maxSleep)
				}
			}

			assert.Equal(t, tc.expectedBurst, tc.limiter.Burst(), "limiter burst mismatch")
		})
	}
}
