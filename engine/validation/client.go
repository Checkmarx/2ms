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
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
