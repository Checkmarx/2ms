package validation

import (
	"fmt"
	"net/http"

	"github.com/checkmarx/2ms/v5/lib/secrets"
	"github.com/rs/zerolog/log"
)

func validateGithub(s *secrets.Secret) (secrets.ValidationResult, string) {
	const githubURL = "https://api.github.com/"

	resp, err := sendValidationRequest(githubURL, fmt.Sprintf("token %s", s.Value))

	if err != nil {
		log.Warn().Err(err).Msg("Failed to validate secret")
		return secrets.UnknownResult, ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return secrets.ValidResult, ""
	}
	return secrets.InvalidResult, ""
}
