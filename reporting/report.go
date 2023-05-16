package reporting

import (
	"fmt"
	"github.com/checkmarx/2ms/config"
	"os"
	"path/filepath"
)

type Report struct {
	TotalItemsScanned int                 `json:"totalItemsScanned"`
	TotalSecretsFound int                 `json:"totalSecretsFound"`
	Results           map[string][]Secret `json:"results"`
}

type Secret struct {
	ID          string `json:"id"`
	Source      string `json:"source"`
	Description string `json:"description"`
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
	fileExtension := format
	var output string
	switch fileExtension {
	case "json":
		output = writeJsonStdOut(*r)
	case "yaml":
		output = writeYamlStdOut(*r)
	case "sarif":
		output = writeSarifStdOut(*r, cfg)
	}
	fmt.Println("Summary:")
	fmt.Printf("%s", output)
}

func (r *Report) WriteFile(reportPath []string, cfg *config.Config) error {
	for _, path := range reportPath {
		file, err := os.Create(path)
		if err != nil {
			return err
		}

		fileExtension := filepath.Ext(path)
		switch fileExtension {
		case ".json":
			err = writeJsonFile(*r, file)
		case ".yaml":
			err = writeYamlFile(*r, file)
		case ".sarif":
			err = writeSarifFile(*r, file, cfg)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
