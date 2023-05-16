package reporting

import (
	"encoding/json"
	"io"
	"log"
)

func writeJsonFile(report Report, w io.WriteCloser) error {
	if len(report.Results) == 0 {
		report.Results = map[string][]Secret{}
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", " ")
	return encoder.Encode(report)
}

func writeJsonStdOut(report Report) string {
	jsonReport, err := json.MarshalIndent(report, "", " ")
	if err != nil {
		log.Fatalf("failed to create Json report with error: %v", err)
	}

	return string(jsonReport)
}
