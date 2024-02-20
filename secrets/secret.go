package secrets

// TODO: rename package to engine and move secrets into subpackage
// Then move the validators into a subpackage too

import (
	"sync"
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
	ValidationStatus validationResult `json:"validationStatus,omitempty"`
}

func isCanValidateRule(ruleID string) bool {
	_, ok := ruleIDToFunction[ruleID]
	return ok
}

func (s *Secret) Validate(wg *sync.WaitGroup) {
	defer wg.Done()
	if f, ok := ruleIDToFunction[s.RuleID]; ok {
		s.ValidationStatus = f(s)
	} else {
		s.ValidationStatus = Unknown
	}
}
