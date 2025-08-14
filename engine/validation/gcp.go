package validation

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/checkmarx/2ms/v4/lib/secrets"
	"github.com/rs/zerolog/log"
)

type errorResponse struct {
	Error struct {
		Message string `json:"message"`
		Details []struct {
			Type     string `json:"@type"`
			Metadata struct {
				Consumer string `json:"consumer"`
			} `json:"metadata,omitempty"`
		} `json:"details"`
	} `json:"error"`
}

func validateGCP(s *secrets.Secret) (secrets.ValidationResult, string) {
	testURL := "https://youtube.googleapis.com/youtube/v3/search?part=snippet&key=" + s.Value

	req, err := http.NewRequestWithContext(context.Background(), "GET", testURL, http.NoBody)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to validate secret")
		return secrets.UnknownResult, ""
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to validate secret")
		return secrets.UnknownResult, ""
	}
	defer resp.Body.Close()

	result, extra, err := checkGCPErrorResponse(resp)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to validate secret")
	}
	return result, extra
}

func checkGCPErrorResponse(resp *http.Response) (secrets.ValidationResult, string, error) {
	if resp.StatusCode == http.StatusOK {
		return secrets.ValidResult, "", nil
	}

	if resp.StatusCode != http.StatusForbidden {
		return secrets.InvalidResult, "", nil
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return secrets.UnknownResult, "", err
	}

	// Unmarshal the response body into the ErrorResponse struct
	var errorResponse errorResponse
	err = json.Unmarshal(bodyBytes, &errorResponse)
	if err != nil {
		return secrets.UnknownResult, "", err
	}

	if strings.Contains(errorResponse.Error.Message, "YouTube Data API v3 has not been used in project") {
		extra := ""
		for _, detail := range errorResponse.Error.Details {
			if detail.Type == "type.googleapis.com/google.rpc.ErrorInfo" {
				extra = detail.Metadata.Consumer
			}
		}
		return secrets.ValidResult, extra, nil
	}

	return secrets.UnknownResult, "", nil
}
