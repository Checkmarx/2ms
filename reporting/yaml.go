package reporting

import (
	"gopkg.in/yaml.v2"
	"log"
)

func writeYaml(report Report) string {
	yamlReport, err := yaml.Marshal(&report)
	if err != nil {
		log.Fatalf("failed to create Yaml report with error: %v", err)
	}

	return string(yamlReport)
}
