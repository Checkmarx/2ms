package validation

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/checkmarx/2ms/lib/secrets"
	"github.com/rs/zerolog/log"
)

type userResponse struct {
	WebURL string `json:"web_url"`
}

func validateGitlab(s *secrets.Secret) (secrets.ValidationResult, string) {
	const gitlabURL = "https://gitlab.com/api/v4/user"

	resp, err := sendValidationRequest(gitlabURL, fmt.Sprintf("Bearer %s", s.Value))

	if err != nil {
		log.Warn().Err(err).Msg("Failed to validate secret")
		return secrets.UnknownResult, ""
	}

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to read response body for Gitlab validation")
			return secrets.ValidResult, ""
		}

		var user userResponse
		if err := json.Unmarshal(bodyBytes, &user); err != nil {
			log.Warn().Err(err).Msg("Failed to unmarshal response body for Gitlab validation")
			return secrets.ValidResult, ""
		}

		return secrets.ValidResult, user.WebURL
	}
	return secrets.InvalidResult, ""
}
