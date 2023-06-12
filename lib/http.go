package lib

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
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

func HttpRequest(method string, url string, autherization IAuthorizationHeader) ([]byte, *http.Response, error) {
	request, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("unexpected error creating an http request %w", err)
	}

	if autherization.GetAuthorizationHeader() != "" {
		request.Header.Set("Authorization", autherization.GetAuthorizationHeader())
	}

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return nil, response, fmt.Errorf("unable to send http request %w", err)
	}

	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, response, fmt.Errorf("error calling http url \"%v\". status code: %v", url, response)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, response, fmt.Errorf("unexpected error reading http response body %w", err)
	}

	return body, response, nil
}
