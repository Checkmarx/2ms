package reporting

import (
	"encoding/json"
	"fmt"
)

func writeJson(report Report) (string, error) {
	jsonReport, err := json.MarshalIndent(report, "", " ")
	if err != nil {
		return "", fmt.Errorf("failed to create Json report with error: %v", err)
	}

	return string(jsonReport), nil
}
