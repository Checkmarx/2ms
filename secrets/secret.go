package secrets

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/rs/zerolog/log"
)

type ValidationResult string

const (
	Valid   ValidationResult = "Valid"
	Revoked ValidationResult = "Revoked"
	Unknown ValidationResult = "Unknown"
)

type Secret struct {
	ID               string           `json:"id"`
	Source           string           `json:"source"`
	RuleID           string           `json:"ruleId"`
	StartLine        int              `json:"startLine"`
	EndLine          int              `json:"endLine"`
	StartColumn      int              `json:"startColumn"`
	EndColumn        int              `json:"endColumn"`
	Value            string           `json:"value"`
	ValidationStatus ValidationResult `json:"validationStatus,omitempty"`
}

type validationFunc = func(*Secret) ValidationResult

var ruleIDToFunction = map[string]validationFunc{
	"github-fine-grained-pat": validateGithub,
	"github-pat":              validateGithub,
}

func (s *Secret) Validate(wg *sync.WaitGroup) {
	defer wg.Done()
	if f, ok := ruleIDToFunction[s.RuleID]; ok {
		s.ValidationStatus = f(s)
	} else {
		s.ValidationStatus = Unknown
	}
}

func validateGithub(s *Secret) ValidationResult {
	const githubURL = "https://api.github.com/"

	req, err := http.NewRequest("GET", githubURL, nil)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to validate secret")
		return Unknown
	}
	req.Header.Set("Authorization", fmt.Sprintf("token %s", s.Value))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to validate secret")
		return Unknown
	}

	if resp.StatusCode == http.StatusOK {
		return Valid
	}
	return Revoked
}
