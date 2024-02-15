package secrets

import "sync"

type ValidationResult string

const (
	Valid   ValidationResult = "Valid"
	Revoked ValidationResult = "Revoked"
	Unknown ValidationResult = "Unknown"
)

type Secret struct {
	ID          string           `json:"id"`
	Source      string           `json:"source"`
	RuleID      string           `json:"ruleId"`
	StartLine   int              `json:"startLine"`
	EndLine     int              `json:"endLine"`
	StartColumn int              `json:"startColumn"`
	EndColumn   int              `json:"endColumn"`
	Value       string           `json:"value"`
	Validation  ValidationResult `json:"validation,omitempty"`
}

type validationFunc = func(*Secret) ValidationResult

var ruleIDToFunction = map[string]validationFunc{
	"GitHub": validateGithub,
}

func (s *Secret) Validate(wg *sync.WaitGroup) {
	defer wg.Done()
	if f, ok := ruleIDToFunction[s.RuleID]; ok {
		s.Validation = f(s)
	} else {
		s.Validation = Unknown
	}
}

func validateGithub(s *Secret) ValidationResult {
	return Unknown
}
