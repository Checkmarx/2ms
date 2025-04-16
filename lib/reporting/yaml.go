package reporting

import (
	"fmt"
	"sort"
	"strings"

	"github.com/checkmarx/2ms/lib/secrets"
)

func writeYaml(report *Report) (string, error) {
	var builder strings.Builder

	builder.WriteString(fmt.Sprintf("totalitemsscanned: %d\n", report.TotalItemsScanned))
	builder.WriteString(fmt.Sprintf("totalsecretsfound: %d\n", report.TotalSecretsFound))
	builder.WriteString("results:\n")

	groupedByID := make(map[string][]*secrets.Secret)
	for _, secretList := range report.Results {
		for _, s := range secretList {
			groupedByID[s.ID] = append(groupedByID[s.ID], s)
		}
	}

	ids := make([]string, 0, len(groupedByID))
	for id := range groupedByID {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		builder.WriteString(fmt.Sprintf("  %s:\n", id))
		for _, s := range groupedByID[id] {
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
			if s.ExtraDetails == nil || len(s.ExtraDetails) == 0 {
				builder.WriteString("      extradetails: {}\n")
			} else {
				builder.WriteString(fmt.Sprintf("      extradetails: %v\n", s.ExtraDetails))
			}
			builder.WriteString(fmt.Sprintf("      cvssscore: %.1f\n", s.CvssScore))
		}
	}

	return builder.String(), nil
}
