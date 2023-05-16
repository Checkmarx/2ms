package reporting

import (
	"encoding/json"
	"log"
)

func writeJson(report Report) string {
	jsonReport, err := json.MarshalIndent(report, "", " ")
	if err != nil {
		log.Fatalf("failed to create Json report with error: %v", err)
	}

	return string(jsonReport)
}
