package secrets

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
