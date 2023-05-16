package reporting

import (
	"gopkg.in/yaml.v2"
	"io"
	"log"
)

func writeYamlFile(report Report, w io.WriteCloser) error {
	if len(report.Results) == 0 {
		report.Results = map[string][]Secret{}
	}
	enc := yaml.NewEncoder(w)
	return enc.Encode(report)
}

func writeYamlStdOut(report Report) string {
	yamlReport, err := yaml.Marshal(&report)
	if err != nil {
		log.Fatalf("failed to create Yaml report with error: %v", err)
	}

	return string(yamlReport)
}
