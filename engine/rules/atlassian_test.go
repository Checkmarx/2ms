package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAtlassian(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "Atlassian validation",
			truePositives: []string{
				"{\n    \"atlassian_token\": \"aa8m68ioy75by0an9xe785f3\"\n}",
				"<atlassianToken>\n    aa8m68ioy75by0an9xe785f3\n</atlassianToken>",
				"atlassian_token: aa8m68ioy75by0an9xe785f3",
				"atlassian_token: \"aa8m68ioy75by0an9xe785f3\"",
				"string atlassianToken = \"aa8m68ioy75by0an9xe785f3\";",
				"atlassianToken := \"aa8m68ioy75by0an9xe785f3\"",
				"$atlassianToken .= \"aa8m68ioy75by0an9xe785f3\"",
				"atlassianToken = 'aa8m68ioy75by0an9xe785f3'",
				"atlassian_token: 'aa8m68ioy75by0an9xe785f3'",
				"var atlassianToken = \"aa8m68ioy75by0an9xe785f3\"",
				"atlassianToken = \"aa8m68ioy75by0an9xe785f3\"",
				"  \"atlassianToken\" => \"aa8m68ioy75by0an9xe785f3\"",
				"atlassian_TOKEN := \"aa8m68ioy75by0an9xe785f3\"",
				"atlassian_TOKEN ::= \"aa8m68ioy75by0an9xe785f3\"",
				"atlassian_TOKEN :::= \"aa8m68ioy75by0an9xe785f3\"",
				"atlassianToken = \"aa8m68ioy75by0an9xe785f3\"",
				"atlassianToken=aa8m68ioy75by0an9xe785f3",
				"{\"config.ini\": \"ATLASSIAN_TOKEN=aa8m68ioy75by0an9xe785f3\\nBACKUP_ENABLED=true\"}",
				"System.setProperty(\"ATLASSIAN_TOKEN\", \"aa8m68ioy75by0an9xe785f3\")",
				"atlassian_TOKEN = \"aa8m68ioy75by0an9xe785f3\"",
				"atlassian_TOKEN ?= \"aa8m68ioy75by0an9xe785f3\"",
				"atlassianToken=\"aa8m68ioy75by0an9xe785f3\"",
				"atlassianToken = aa8m68ioy75by0an9xe785f3",
				"var atlassianToken string = \"aa8m68ioy75by0an9xe785f3\"",
				"atlassianToken := `aa8m68ioy75by0an9xe785f3`",
				"String atlassianToken = \"aa8m68ioy75by0an9xe785f3\";",
				"confluenceToken = \"aa8m68ioy75by0an9xe785f3\"",
				"confluence_TOKEN ::= \"aa8m68ioy75by0an9xe785f3\"",
				"confluence_TOKEN ?= \"aa8m68ioy75by0an9xe785f3\"",
				"confluenceToken = \"aa8m68ioy75by0an9xe785f3\"",
				"{\"config.ini\": \"CONFLUENCE_TOKEN=aa8m68ioy75by0an9xe785f3\\nBACKUP_ENABLED=true\"}",
				"var confluenceToken string = \"aa8m68ioy75by0an9xe785f3\"",
				"confluenceToken := \"aa8m68ioy75by0an9xe785f3\"",
				"confluenceToken = 'aa8m68ioy75by0an9xe785f3'",
				"confluence_TOKEN :::= \"aa8m68ioy75by0an9xe785f3\"",
				"confluenceToken=aa8m68ioy75by0an9xe785f3",
				"{\n    \"confluence_token\": \"aa8m68ioy75by0an9xe785f3\"\n}",
				"<confluenceToken>\n    aa8m68ioy75by0an9xe785f3\n</confluenceToken>",
				"confluence_token: \"aa8m68ioy75by0an9xe785f3\"",
				"string confluenceToken = \"aa8m68ioy75by0an9xe785f3\";",
				"  \"confluenceToken\" => \"aa8m68ioy75by0an9xe785f3\"",
				"confluenceToken=\"aa8m68ioy75by0an9xe785f3\"",
				"confluenceToken := `aa8m68ioy75by0an9xe785f3`",
				"String confluenceToken = \"aa8m68ioy75by0an9xe785f3\";",
				"var confluenceToken = \"aa8m68ioy75by0an9xe785f3\"",
				"$confluenceToken .= \"aa8m68ioy75by0an9xe785f3\"",
				"System.setProperty(\"CONFLUENCE_TOKEN\", \"aa8m68ioy75by0an9xe785f3\")",
				"confluence_TOKEN = \"aa8m68ioy75by0an9xe785f3\"",
				"confluence_TOKEN := \"aa8m68ioy75by0an9xe785f3\"",
				"confluenceToken = aa8m68ioy75by0an9xe785f3",
				"confluence_token: aa8m68ioy75by0an9xe785f3",
				"confluence_token: 'aa8m68ioy75by0an9xe785f3'",
				"jiraToken=dldtlx3vab779zdxfrmoc099",
				"{\n    \"jira_token\": \"dldtlx3vab779zdxfrmoc099\"\n}",
				"{\"config.ini\": \"JIRA_TOKEN=dldtlx3vab779zdxfrmoc099\\nBACKUP_ENABLED=true\"}",
				"jira_token: dldtlx3vab779zdxfrmoc099",
				"jira_token: 'dldtlx3vab779zdxfrmoc099'",
				"jiraToken := \"dldtlx3vab779zdxfrmoc099\"",
				"System.setProperty(\"JIRA_TOKEN\", \"dldtlx3vab779zdxfrmoc099\")",
				"  \"jiraToken\" => \"dldtlx3vab779zdxfrmoc099\"",
				"String jiraToken = \"dldtlx3vab779zdxfrmoc099\";",
				"$jiraToken .= \"dldtlx3vab779zdxfrmoc099\"",
				"jiraToken = \"dldtlx3vab779zdxfrmoc099\"",
				"jira_TOKEN = \"dldtlx3vab779zdxfrmoc099\"",
				"jira_TOKEN ::= \"dldtlx3vab779zdxfrmoc099\"",
				"jira_TOKEN ?= \"dldtlx3vab779zdxfrmoc099\"",
				"jiraToken = dldtlx3vab779zdxfrmoc099",
				"<jiraToken>\n    dldtlx3vab779zdxfrmoc099\n</jiraToken>",
				"jira_token: \"dldtlx3vab779zdxfrmoc099\"",
				"var jiraToken string = \"dldtlx3vab779zdxfrmoc099\"",
				"var jiraToken = \"dldtlx3vab779zdxfrmoc099\"",
				"jiraToken = 'dldtlx3vab779zdxfrmoc099'",
				"jira_TOKEN := \"dldtlx3vab779zdxfrmoc099\"",
				"jiraToken=\"dldtlx3vab779zdxfrmoc099\"",
				"jiraToken = \"dldtlx3vab779zdxfrmoc099\"",
				"string jiraToken = \"dldtlx3vab779zdxfrmoc099\";",
				"jiraToken := `dldtlx3vab779zdxfrmoc099`",
				"jira_TOKEN :::= \"dldtlx3vab779zdxfrmoc099\"",
				"JIRA_API_TOKEN=HXe8DGg1iJd2AopzyxkFB7F2",
				"jiraToken = \"ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6\"",
				"System.setProperty(\"JIRA_TOKEN\", \"ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6\")",
				"  \"jiraToken\" => \"ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6\"",
				"jira_TOKEN := \"ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6\"",
				"jiraToken=ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6",
				"{\n    \"jira_token\": \"ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6\"\n}",
				"<jiraToken>\n    ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6\n</jiraToken>",
				"jira_token: ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6",
				"jiraToken := \"ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6\"",
				"jiraToken = 'ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6'",
				"jira_TOKEN = \"ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6\"",
				"jiraToken = \"ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6\"",
				"string jiraToken = \"ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6\";",
				"var jiraToken string = \"ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6\"",
				"jira_TOKEN ::= \"ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6\"",
				"jira_TOKEN ?= \"ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6\"",
				"jiraToken=\"ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6\"",
				"jiraToken = ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6",
				"jira_token: \"ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6\"",
				"jiraToken := `ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6`",
				"$jiraToken .= \"ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6\"",
				"jira_TOKEN :::= \"ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6\"",
				"{\"config.ini\": \"JIRA_TOKEN=ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6\\nBACKUP_ENABLED=true\"}",
				"jira_token: 'ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6'",
				"String jiraToken = \"ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6\";",
				"var jiraToken = \"ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6\"",
			},
			falsePositives: []string{"getPagesInConfluenceSpace,searchConfluenceUsingCql"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fmt.Println("truePositives := []string{")
			for _, s := range tt.truePositives {
				fmt.Printf("\t%q,\n", s) // %q prints the string with quotes
			}
			fmt.Println("},")
			rule := ConvertNewRuleToGitleaksRule(Atlassian())
			d := createSingleRuleDetector(rule)

			// validate true positives if any specified
			for _, truePositive := range tt.truePositives {
				findings := d.DetectString(truePositive)
				assert.GreaterOrEqual(t, len(findings), 1, fmt.Sprintf("failed to detect true positive: %s", truePositive))
			}

			// validate false positives if any specified
			for _, falsePositive := range tt.falsePositives {
				findings := d.DetectString(falsePositive)
				assert.Equal(t, 0, len(findings), fmt.Sprintf("unexpectedly found false positive: %s", falsePositive))
			}
		})
	}
}
