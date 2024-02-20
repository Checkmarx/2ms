package secrets

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/rs/zerolog/log"
)

type validationResult string

const (
	Valid   validationResult = "Valid"
	Revoked validationResult = "Revoked"
	Unknown validationResult = "Unknown"
)

type compared int

const (
	first  compared = -1
	second compared = 1
	equal  compared = 0
)

func (v validationResult) CompareTo(other validationResult) compared {
	if v == other {
		return equal
	}
	if v == Unknown {
		return second
	}
	if other == Unknown {
		return first
	}
	if v == Revoked {
		return second
	}
	return first
}

type validationFunc = func(*Secret) validationResult

var ruleIDToFunction = map[string]validationFunc{
	"github-fine-grained-pat": validateGithub,
	"github-pat":              validateGithub,
}

func validateGithub(s *Secret) validationResult {
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
		secret.ValidationStatus = validate(secret)
	} else if !v.pairsCollector.addIfNeeded(secret) {
		secret.ValidationStatus = Unknown
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
