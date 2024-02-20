package engine

// TODO: rename package to engine and move secrets into subpackage
// Then move the validators into a subpackage too

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
	if _, ok := ruleIDToFunction[ruleID]; ok {
		return true
	}
	if _, ok := ruleToGeneralKey[ruleID]; ok {
		return true
	}

	return false
}
