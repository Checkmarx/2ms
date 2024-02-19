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

type validationFunc = func(*Secret) ValidationResult

var ruleIDToFunction = map[string]validationFunc{
	"github-fine-grained-pat": validateGithub,
	"github-pat":              validateGithub,
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

type Validator struct {
	pairsCollector *pairsCollector
}

func NewValidator() *Validator {
	return &Validator{pairsCollector: newPairsCollector()}
}

func (v *Validator) RegisterForValidation(secret *Secret) {
	if validate, ok := ruleIDToFunction[secret.RuleID]; ok {
		secret.Validation = validate(secret)
	} else if !v.pairsCollector.addIfNeeded(secret) {
		secret.Validation = Unknown
	}
}

func (v *Validator) Validate() {
	wg := &sync.WaitGroup{}
	for generalKey, bySource := range v.pairsCollector.pairs {
		for _, byRule := range bySource {
			// test all pairs per source
			wg.Add(1)
			v.pairsCollector.validate(generalKey, byRule, wg)
		}
	}
}
