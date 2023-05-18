package reporting

import (
	"fmt"
	"github.com/checkmarx/2ms/config"
	"github.com/checkmarx/2ms/secrets"
	"os"
	"path/filepath"
	"strings"
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
	ID          string   `json:"id"`
	Links       []string `json:"links"`
	Source      string   `json:"source"`
	Description string   `json:"description"`
	StartLine   int      `json:"startLine"`
	EndLine     int      `json:"endLine"`
	StartColumn int      `json:"startColumn"`
	EndColumn   int      `json:"endColumn"`
	Value       string   `json:"value"`
}

func Init() *Report {
	return &Report{
		Results: make(map[string][]Secret),
	}
}

func (r *Report) AddSecret(finding secrets.Finding) {
	done := false

	// If secret already exists, just add the link of new finding
	if len(r.Results[finding.ID]) > 0 {
		for i, s := range r.Results[finding.ID] {
			if s.Value == finding.Secret {
				s := &r.Results[finding.ID][i]
				s.Links = append(s.Links, finding.Source)
				done = true
				break
			}
		}
	}
	// If secret don't exist on a specific source or if source doesn't exist just create the secret
	if !done {
		secret := Secret{ID: finding.ID, Links: []string{finding.Source}, Description: finding.Description, StartLine: finding.StartLine, EndLine: finding.EndLine, StartColumn: finding.StartColumn, EndColumn: finding.EndColumn, Value: finding.Secret}
		r.Results[finding.ID] = append(r.Results[finding.ID], secret)
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
