package reporting

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/checkmarx/2ms/config"
)

const (
	jsonFormat  = "json"
	yamlFormat  = "yaml"
	sarifFormat = "sarif"
)

type Report struct {
	TotalItemsScanned int                 `json:"totalItemsScanned"`
	TotalSecretsFound int                 `json:"totalSecretsFound"`
	Results           map[string][]Secret `json:"results"`
}

type Secret struct {
	ID          string `json:"id"`
	Source      string `json:"source"`
	RuleID      string `json:"ruleId"`
	StartLine   int    `json:"startLine"`
	EndLine     int    `json:"endLine"`
	StartColumn int    `json:"startColumn"`
	EndColumn   int    `json:"endColumn"`
	Value       string `json:"value"`
}

func Init() *Report {
	return &Report{
		Results: make(map[string][]Secret),
	}
}

func (r *Report) ShowReport(format string, cfg *config.Config) {
	output := r.getOutput(format, cfg)

	fmt.Println("Summary:")
	fmt.Print(output)
}

func (r *Report) WriteFile(reportPath []string, cfg *config.Config) error {
	for _, path := range reportPath {
		file, err := os.Create(path)
		if err != nil {
			return err
		}

		fileExtension := filepath.Ext(path)
		format := strings.TrimPrefix(fileExtension, ".")
		output := r.getOutput(format, cfg)

		_, err = file.WriteString(output)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *Report) getOutput(format string, cfg *config.Config) string {
	var output string
	switch format {
	case jsonFormat:
		output = writeJson(*r)
	case yamlFormat:
		output = writeYaml(*r)
	case sarifFormat:
		output = writeSarif(*r, cfg)
	}
	return output
}
