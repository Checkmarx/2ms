package reporting

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

func writeYaml(report *Report) (string, error) {
	var builder strings.Builder

	builder.WriteString(fmt.Sprintf("totalitemsscanned: %d\n", report.TotalItemsScanned))
	builder.WriteString(fmt.Sprintf("totalsecretsfound: %d\n", report.TotalSecretsFound))
	builder.WriteString("results:\n")

	for _, secretsList := range report.Results {
		if len(secretsList) > 0 {
			builder.WriteString(fmt.Sprintf("  %s:\n", secretsList[0].ID))
		}
		for _, s := range secretsList {
			builder.WriteString("    - id: " + s.ID + "\n")
			builder.WriteString("      source: " + s.Source + "\n")
			builder.WriteString("      ruleid: " + s.RuleID + "\n")
			builder.WriteString(fmt.Sprintf("      startline: %d\n", s.StartLine))
			builder.WriteString(fmt.Sprintf("      endline: %d\n", s.EndLine))
			builder.WriteString(fmt.Sprintf("      linecontent: %q\n", s.LineContent))
			builder.WriteString(fmt.Sprintf("      startcolumn: %d\n", s.StartColumn))
			builder.WriteString(fmt.Sprintf("      endcolumn: %d\n", s.EndColumn))
			builder.WriteString("      value: " + s.Value + "\n")
			builder.WriteString(fmt.Sprintf("      validationstatus: %q\n", fmt.Sprintf("%v", s.ValidationStatus)))
			builder.WriteString("      ruledescription: " + s.RuleDescription + "\n")
			if len(s.ExtraDetails) > 0 {
				builder.WriteString("      extradetails:\n")
				marshaled, err := yaml.Marshal(s.ExtraDetails)
				if err != nil {
					builder.WriteString(fmt.Sprintf("        error: %v\n", err))
				} else {
					lines := strings.Split(string(marshaled), "\n")
					for _, line := range lines {
						if line != "" {
							builder.WriteString("        " + line + "\n")
						}
					}
				}
			}
			builder.WriteString(fmt.Sprintf("      cvssscore: %.1f\n", s.CvssScore))
		}
	}

	return builder.String(), nil
}
