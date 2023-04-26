package reporting

import (
	"fmt"
	"github.com/checkmarx/2ms/secrets"
)

type Report struct {
	Results           map[string][]Secret
	TotalItemsScanned int
	TotalSecretsFound int
}

type Secret struct {
	ID          string
	Links       []string
	Description string
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int
	Value       string
}

func Init() *Report {
	return &Report{
		Results:           make(map[string][]Secret),
		TotalItemsScanned: 0,
		TotalSecretsFound: 0,
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
		fmt.Printf("- Item ID: %s\n", source)
		fmt.Println("  - Secrets:")
		for _, secret := range secrets {
			fmt.Printf("   - Type: %s\n", secret.Description)
			fmt.Printf("    - Links: %d\n", len(secret.Links))
			for _, link := range secret.Links {
				fmt.Printf("      - %s\n", link)
			}
			fmt.Printf("    - Location: %d-%d\n", secret.StartColumn, secret.EndColumn)
			fmt.Printf("    - Value: %.40s\n", secret.Value)
		}
	}
}
