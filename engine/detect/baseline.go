package detect

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zricethezav/gitleaks/v8/report"
)

// IsNew returns true if the finding is not present in the baseline slice.
func IsNew(finding *report.Finding, baseline []report.Finding) bool {
	for i := range baseline {
		if findingsEqualExceptFingerprint(finding, &baseline[i]) {
			return false
		}
	}
	return true
}

// findingsEqualExceptFingerprint compares all fields except Fingerprint.
func findingsEqualExceptFingerprint(a, b *report.Finding) bool {
	return a.Author == b.Author &&
		a.Commit == b.Commit &&
		a.Date == b.Date &&
		a.Description == b.Description &&
		a.Email == b.Email &&
		a.EndColumn == b.EndColumn &&
		a.EndLine == b.EndLine &&
		a.Entropy == b.Entropy &&
		a.File == b.File &&
		// Omit checking Fingerprint - if the format of the fingerprint changes, the users will see unexpected behavior
		a.Match == b.Match &&
		a.Message == b.Message &&
		a.RuleID == b.RuleID &&
		a.Secret == b.Secret &&
		a.StartColumn == b.StartColumn &&
		a.StartLine == b.StartLine
}

func LoadBaseline(baselinePath string) ([]report.Finding, error) {
	bytes, err := os.ReadFile(baselinePath)
	if err != nil {
		return nil, fmt.Errorf("could not open %s", baselinePath)
	}

	var previousFindings []report.Finding
	err = json.Unmarshal(bytes, &previousFindings)
	if err != nil {
		return nil, fmt.Errorf("the format of the file %s is not supported", baselinePath)
	}

	return previousFindings, nil
}

func (d *Detector) AddBaseline(baselinePath, source string) error {
	if baselinePath != "" {
		absoluteSource, err := filepath.Abs(source)
		if err != nil {
			return err
		}

		absoluteBaseline, err := filepath.Abs(baselinePath)
		if err != nil {
			return err
		}

		relativeBaseline, err := filepath.Rel(absoluteSource, absoluteBaseline)
		if err != nil {
			return err
		}

		baseline, err := LoadBaseline(baselinePath)
		if err != nil {
			return err
		}

		d.baseline = baseline
		baselinePath = relativeBaseline
	}

	d.baselinePath = baselinePath
	return nil
}
