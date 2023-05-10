package reporting

import (
	"fmt"
	"github.com/zricethezav/gitleaks/v8/config"
	"os"
	"path/filepath"
	"strings"
)

type Report struct {
	Results           map[string][]Secret
	TotalItemsScanned int
	TotalSecretsFound int
}

type Secret struct {
	ID          string
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
		itemId := getItemId(source)
		fmt.Printf("- Item ID: %s\n", itemId)
		fmt.Printf(" - Item Full Path: %s\n", source)
		fmt.Println("  - Secrets:")
		for _, secret := range secrets {
			fmt.Printf("   - Type: %s\n", secret.Description)
			fmt.Printf("    - Value: %.40s\n", secret.Value)
		}
	}
}

func getItemId(fullPath string) string {
	var itemId string
	if strings.Contains(fullPath, "/") {
		itemLinkStrings := strings.Split(fullPath, "/")
		itemId = itemLinkStrings[len(itemLinkStrings)-1]
	}
	if strings.Contains(fullPath, "\\") {
		itemId = filepath.Base(fullPath)
	}
	return itemId
}

func (r *Report) Write(reportPath string, orderedRules []config.Rule) error {
	file, err := os.Create(reportPath)
	if err != nil {
		return err
	}
	writeSarif(*r, file, orderedRules)

	return nil
}
