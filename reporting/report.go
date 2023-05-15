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

func (r *Report) ShowReport() {
	fmt.Println("Summary:")
	fmt.Printf("- Total items scanned: %d\n", r.TotalItemsScanned)
	fmt.Printf("- Total items with secrets: %d\n", len(r.Results))
	if len(r.Results) > 0 {
		fmt.Printf("- Total secrets found: %d\n", r.TotalSecretsFound)
		fmt.Println("Detailed Report:")
		r.generateResultsReport()
	}

}

func (r *Report) generateResultsReport() {
	for source, secrets := range r.Results {
		fmt.Printf(" - Item Source: %s\n", source)
		fmt.Println("  - Secrets:")
		for _, secret := range secrets {
			fmt.Printf("   - Item ID: %s\n", secret.ID)
			fmt.Printf("   - Type: %s\n", secret.Description)
			fmt.Printf("   - Value: %.40s\n", secret.Value)
		}
	}
}

func (r *Report) Write(reportPath []string, cfg *config.Config) error {
	for _, path := range reportPath {
		file, err := os.Create(path)
		if err != nil {
			return err
		}

		fileExtension := filepath.Ext(path)
		switch fileExtension {
		case ".json":
			err = writeJson(*r, file)
		case ".yaml":
			err = writeYaml(*r, file)
		case ".sarif":
			err = writeSarif(*r, file, cfg)
		}
	}
	return nil
}
