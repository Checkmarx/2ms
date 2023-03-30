package reporting

import (
	"fmt"
	"strings"
)

func ShowReport(report Report) {
	fmt.Println("Summary:")
	fmt.Printf("- Total items scanned: %d\n", report.TotalItemsScanned)
	fmt.Printf("- Total items with secrets: %d\n", len(report.Results))
	if len(report.Results) > 0 {
		fmt.Printf("- Total secrets found: %d\n", report.TotalSecretsFound)
		fmt.Println("Detailed Report:")
		generateResultsReport(report.Results)
	}

}

func generateResultsReport(results map[string][]Secret) {
	for source, secrets := range results {
		itemLink := getItemId(source)
		fmt.Printf("- Item ID: %s\n", itemLink)
		fmt.Printf(" - Item Link: %s\n", source)
		fmt.Println("  - Secrets:")
		for _, secret := range secrets {
			fmt.Printf("   - Type: %s\n", secret.Description)
			fmt.Printf("    - Location: %d-%d\n", secret.StartColumn, secret.EndColumn)
			fmt.Printf("    - Value: %.40s\n", secret.Value)
		}
	}
}

func getItemId(fullPath string) string {
	itemLinkStrings := strings.Split(fullPath, "/")
	itemLink := itemLinkStrings[len(itemLinkStrings)-1]
	return itemLink
}

type Report struct {
	Results           map[string][]Secret
	TotalItemsScanned int
	TotalSecretsFound int
}

type Secret struct {
	Description string
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int
	Value       string
}
