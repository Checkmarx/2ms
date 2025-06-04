package utils

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"
)

type ICredentials interface {
	GetCredentials() (string, string)
}

func CreateBasicAuthCredentials(credentials ICredentials) string {
	username, password := credentials.GetCredentials()
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password)))
}

type IAuthorizationHeader interface {
	GetAuthorizationHeader() string
}

type RetrySettings struct {
	MaxRetries int
	ErrorCodes []int
}

func HttpRequest(method string, url string, authorization IAuthorizationHeader, retry RetrySettings) ([]byte, *http.Response, error) {
	request, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("unexpected error creating an http request %w", err)
	}

	if authorization.GetAuthorizationHeader() != "" {
		request.Header.Set("Authorization", authorization.GetAuthorizationHeader())
	}

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return nil, response, fmt.Errorf("unable to send http request %w", err)
	}

	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if retry.MaxRetries > 0 {
			for _, code := range retry.ErrorCodes {
				if response.StatusCode == code {
					log.Warn().Msgf("retrying http request %v", url)
					return HttpRequest(method, url, authorization, RetrySettings{MaxRetries: retry.MaxRetries - 1, ErrorCodes: retry.ErrorCodes})
				}
			}
		}
		return nil, response, fmt.Errorf("error calling http url \"%v\". status code: %v", url, response)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, response, fmt.Errorf("unexpected error reading http response body %w", err)
	}

	return body, response, nil
}
