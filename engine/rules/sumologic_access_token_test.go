package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
)

func TestSumoLogicAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name:          "SumoLogicAccessToken validation",
			truePositives: []string{},
			falsePositives: []string{
				`#   SUMO_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`, // gitleaks:allow
				"-e SUMO_ACCESS_KEY=`etcdctl get /sumologic_secret`",
				`SUMO_ACCESS_KEY={SumoAccessKey}`,
				`SUMO_ACCESS_KEY=${SUMO_ACCESS_KEY:=$2}`,
				`sumo_access_key   = "<SUMOLOGIC ACCESS KEY>"`,
				`SUMO_ACCESS_KEY: AbCeFG123`,
				`sumOfExposures = 3Kof2VffNQ0QgYIhXUPJosVlCaQKm2hfpWE6F1fT9YGY74blQBIPsrkCcf1TwKE5;`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tps := utils.GenerateSampleSecrets("sumo", secrets.NewSecret(utils.AlphaNumeric("64")))
			tps = append(tps,
				`export SUMOLOGIC_ACCESSKEY="3HSa1hQfz6BYzlxf7Yb1WKG3Hyovm56LMFChV2y9LgkRipsXCujcLb5ej3oQUJlx"`, // gitleaks:allow
				`SUMO_ACCESS_KEY: gxq3rJQkS6qovOg9UY2Q70iH1jFZx0WBrrsiAYv4XHodogAwTKyLzvFK4neRN8Dk`,             // gitleaks:allow
				`SUMOLOGIC_ACCESSKEY: 9RITWb3I3kAnSyUolcVJq4gwM17JRnQK8ugRaixFfxkdSl8ys17ZtEL3LotESKB7`,         // gitleaks:allow
				`sumo_access_key = "3Kof2VffNQ0QgYIhXUPJosVlCaQKm2hfpWE6F1fT9YGY74blQBIPsrkCcf1TwKE5"`,          // gitleaks:allow
			)
			fmt.Println("truePositives := []string{")
			for _, s := range tps {
				fmt.Printf("\t%q,\n", s) // %q prints the string with quotes
			}
			fmt.Println("},")
			fmt.Println("falsePositives := []string{")
			for _, s := range tt.falsePositives {
				fmt.Printf("\t%q,\n", s) // %q prints the string with quotes
			}
			fmt.Println("},")
			rule := ConvertNewRuleToGitleaksRule(SumoLogicAccessToken())
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
