package validation

import (
	"fmt"
	"net/http"

	"github.com/checkmarx/2ms/lib/secrets"
	"github.com/rs/zerolog/log"
)

func validateGitlab(s *secrets.Secret) (secrets.ValidationResult, string) {
	const gitlabURL = "https://gitlab.com/api/v4/user"

	resp, err := sendValidationRequest(gitlabURL, fmt.Sprintf("Bearer %s", s.Value))

	if err != nil {
		log.Warn().Err(err).Msg("Failed to validate secret")
		return secrets.UnknownResult, ""
	}

	if resp.StatusCode == http.StatusOK {
		return secrets.ValidResult, ""
	}
	return secrets.RevokedResult, ""
}
