package validation

import (
	"fmt"
	"net/http"

	"github.com/checkmarx/2ms/lib/secrets"
	"github.com/rs/zerolog/log"
)

func validateGithub(s *secrets.Secret) secrets.ValidationResult {
	const githubURL = "https://api.github.com/"

	req, err := http.NewRequest("GET", githubURL, nil)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to validate secret")
		return secrets.UnknownResult
	}
	req.Header.Set("Authorization", fmt.Sprintf("token %s", s.Value))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to validate secret")
		return secrets.UnknownResult
	}

	if resp.StatusCode == http.StatusOK {
		return secrets.ValidResult
	}
	return secrets.RevokedResult
}
