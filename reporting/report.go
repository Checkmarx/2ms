package reporting

import (
	"fmt"
	"github.com/checkmarx/2ms/config"
	"os"
	"path/filepath"
)

type Report struct {
	Results           map[string][]Secret
	TotalItemsScanned int
	TotalSecretsFound int
}

type Secret struct {
	ID          string
	Source      string
	Description string
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int
	Value       string
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

func (r *Report) Write(reportPath string, cfg *config.Config) error {
	file, err := os.Create(reportPath)
	if err != nil {
		return err
	}

	fileExtension := filepath.Ext(reportPath)
	switch fileExtension {
	//case ".json":
	//	err = writeJson(*r, file, cfg)
	//case ".csv":
	//	err = writeCsv(*r, file, cfg)
	case ".sarif":
		err = writeSarif(*r, file, cfg)
	}

	return err
}
