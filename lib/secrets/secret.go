package secrets

type ValidationResult string

const (
	ValidResult   ValidationResult = "Valid"
	InvalidResult ValidationResult = "Invalid"
	UnknownResult ValidationResult = "Unknown"
)

type compared int

const (
	first  compared = -1
	second compared = 1
	equal  compared = 0
)

func (v ValidationResult) CompareTo(other ValidationResult) compared {
	if v == other {
		return equal
	}
	if v == UnknownResult {
		return second
	}
	if other == UnknownResult {
		return first
	}
	if v == InvalidResult {
		return second
	}
	return first
}

type Secret struct {
	ID               string                 `json:"id"`
	Source           string                 `json:"source"`
	RuleID           string                 `json:"ruleId"`
	StartLine        int                    `json:"startLine"`
	EndLine          int                    `json:"endLine"`
	Line             string                 `json:"line"`
	StartColumn      int                    `json:"startColumn"`
	EndColumn        int                    `json:"endColumn"`
	Value            string                 `json:"value"`
	ValidationStatus ValidationResult       `json:"validationStatus,omitempty"`
	ExtraDetails     map[string]interface{} `json:"extraDetails,omitempty"`
}
