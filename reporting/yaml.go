package reporting

import (
	"gopkg.in/yaml.v2"
	"io"
)

func writeYaml(report Report, w io.WriteCloser) error {
	if len(report.Results) == 0 {
		report.Results = map[string][]Secret{}
	}
	enc := yaml.NewEncoder(w)
	return enc.Encode(report)
}
