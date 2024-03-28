package validation

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/checkmarx/2ms/lib/secrets"
	"github.com/rs/zerolog/log"
)

type ErrorResponse struct {
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
}

func validateGCP(s *secrets.Secret) secrets.ValidationResult {
	testURL := "https://youtube.googleapis.com/youtube/v3/search?part=snippet&key=" + s.Value

	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to validate secret")
		return secrets.UnknownResult
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to validate secret")
		return secrets.UnknownResult
	}

	result, err := checkGCPErrorResponse(resp)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to validate secret")
	}
	return result
}

func checkGCPErrorResponse(resp *http.Response) (secrets.ValidationResult, error) {
	if resp.StatusCode == http.StatusOK {
		return secrets.ValidResult, nil
	}

	if resp.StatusCode != http.StatusForbidden {
		return secrets.RevokedResult, nil
	}

	// Read the response body
	body := make([]byte, resp.ContentLength)
	count, err := resp.Body.Read(body)
	if err != nil {
		return secrets.UnknownResult, err
	}
	defer resp.Body.Close()

	// Unmarshal the response body into the ErrorResponse struct
	var errorResponse ErrorResponse
	err = json.Unmarshal(body[:count], &errorResponse)
	if err != nil {
		return secrets.UnknownResult, err
	}

	if strings.Contains(errorResponse.Error.Message, "YouTube Data API v3 has not been used in project") {
		return secrets.ValidResult, nil
	}

	return secrets.UnknownResult, nil

}
