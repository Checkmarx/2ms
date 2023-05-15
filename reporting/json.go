package reporting

import (
	"encoding/json"
	"io"
)

func writeJson(report Report, w io.WriteCloser) error {
	if len(report.Results) == 0 {
		report.Results = map[string][]Secret{}
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", " ")
	return encoder.Encode(report)
}
