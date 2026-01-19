package reporting

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

func writeYaml(report *Report) (string, error) {
	estimatedSize := 1024 + len(report.Results)*512
	var builder strings.Builder
	builder.Grow(estimatedSize)

	fmt.Fprintf(&builder, "totalitemsscanned: %d\n", report.TotalItemsScanned)
	fmt.Fprintf(&builder, "totalsecretsfound: %d\n", report.TotalSecretsFound)
	if report.TotalSecretsFound == 0 {
		fmt.Fprint(&builder, "results: {}\n")
	} else {
		builder.WriteString("results:\n")
		for _, secretsList := range report.Results {
			if len(secretsList) > 0 {
				fmt.Fprintf(&builder, "  %s:\n", secretsList[0].ID)
			}
			for _, s := range secretsList {
				fmt.Fprintf(&builder, "    - id: %s\n", s.ID)
				fmt.Fprintf(&builder, "      source: %s\n", s.Source)
				fmt.Fprintf(&builder, "      ruleid: %s\n", s.RuleID)
				fmt.Fprintf(&builder, "      rulename: %s\n", s.RuleName)
				fmt.Fprintf(&builder, "      rulecategory: %s\n", s.RuleCategory)
				fmt.Fprintf(&builder, "      startline: %d\n", s.StartLine)
				fmt.Fprintf(&builder, "      endline: %d\n", s.EndLine)
				fmt.Fprintf(&builder, "      linecontent: %q\n", s.LineContent)
				fmt.Fprintf(&builder, "      startcolumn: %d\n", s.StartColumn)
				fmt.Fprintf(&builder, "      endcolumn: %d\n", s.EndColumn)
				fmt.Fprintf(&builder, "      value: %s\n", s.Value)
				fmt.Fprintf(&builder, "      validationstatus: %q\n", fmt.Sprintf("%v", s.ValidationStatus))
				fmt.Fprintf(&builder, "      ruledescription: %s\n", s.RuleDescription)
				if len(s.ExtraDetails) > 0 {
					builder.WriteString("      extradetails:\n")
					marshaled, err := yaml.Marshal(s.ExtraDetails)
					if err != nil {
						fmt.Fprintf(&builder, "        error: %v\n", err)
						return "", err
					} else {
						lines := strings.Split(string(marshaled), "\n")
						for _, line := range lines {
							if line != "" {
								fmt.Fprintf(&builder, "        %s\n", line)
							}
						}
					}
				}
				fmt.Fprintf(&builder, "      severity: %s\n", s.Severity)
				fmt.Fprintf(&builder, "      cvssscore: %.1f\n", s.CvssScore)
			}
		}
	}

	return builder.String(), nil
}
