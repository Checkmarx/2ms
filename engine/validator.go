package engine

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/checkmarx/2ms/lib/secrets"
	"github.com/rs/zerolog/log"
)

type validationFunc = func(*secrets.Secret) secrets.ValidationResult

var ruleIDToFunction = map[string]validationFunc{
	"github-fine-grained-pat": validateGithub,
	"github-pat":              validateGithub,
}

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

type Validator struct {
	pairsCollector *pairsCollector
}

func NewValidator() *Validator {
	return &Validator{pairsCollector: newPairsCollector()}
}

func (v *Validator) RegisterForValidation(secret *secrets.Secret) {
	if validate, ok := ruleIDToFunction[secret.RuleID]; ok {
		secret.ValidationStatus = validate(secret)
	} else if !v.pairsCollector.addIfNeeded(secret) {
		secret.ValidationStatus = secrets.UnknownResult
	}
}

func (v *Validator) Validate() {
	wg := &sync.WaitGroup{}
	for generalKey, bySource := range v.pairsCollector.pairs {
		for _, byRule := range bySource {
			wg.Add(1)
			v.pairsCollector.validate(generalKey, byRule, wg)
		}
	}
	wg.Wait()
}

func isCanValidateRule(ruleID string) bool {
	if _, ok := ruleIDToFunction[ruleID]; ok {
		return true
	}
	if _, ok := ruleToGeneralKey[ruleID]; ok {
		return true
	}

	return false
}
