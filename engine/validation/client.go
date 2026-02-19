package validation

import (
	"context"
	"net/http"
)

func sendValidationRequest(endpoint, authorization string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), "GET", endpoint, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", authorization)

	// TODO: do not recreate this client for each request
	client := &http.Client{}
	// #nosec G704 -- URL is hardcoded in both github and gitlab uses, only query params contain credentials being validated
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
