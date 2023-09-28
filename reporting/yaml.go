package reporting

import (
	"gopkg.in/yaml.v2"
)

func writeYaml(report Report) (string, error) {
	yamlReport, err := yaml.Marshal(&report)
	if err != nil {
		return "", err
	}

	return string(yamlReport), nil
}
