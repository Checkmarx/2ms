package validation

import (
	"sync"

	"github.com/checkmarx/2ms/v3/engine/extra"
	"github.com/checkmarx/2ms/v3/lib/secrets"
)

type validationFunc = func(*secrets.Secret) (secrets.ValidationResult, string)

var ruleIDToFunction = map[string]validationFunc{
	"github-fine-grained-pat": validateGithub,
	"github-pat":              validateGithub,
	"gitlab-pat":              validateGitlab,
	"gcp-api-key":             validateGCP,
}

type Validator struct {
	pairsCollector *pairsCollector
}

func NewValidator() *Validator {
	return &Validator{pairsCollector: newPairsCollector()}
}

func (v *Validator) RegisterForValidation(secret *secrets.Secret) {
	if validate, ok := ruleIDToFunction[secret.RuleID]; ok {
		status, extra := validate(secret)
		secret.ValidationStatus = status
		addExtraToSecret(secret, extra)
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

func IsCanValidateRule(ruleID string) bool {
	if _, ok := ruleIDToFunction[ruleID]; ok {
		return true
	}
	if _, ok := ruleToGeneralKey[ruleID]; ok {
		return true
	}

	return false
}

func addExtraToSecret(secret *secrets.Secret, extraData string) {
	if extraData == "" {
		return
	}

	if secret.ExtraDetails == nil {
		secret.ExtraDetails = make(map[string]interface{})
	}

	extra.UpdateExtraField(secret, "validationDetails", extraData)
}
