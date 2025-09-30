package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
)

func TestClickhouseCloudApiSecretKey(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "ClickhouseCloudApiSecretKey validation",
			truePositives: []string{
				"ClickHouse_token: 4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z",
				"string ClickHouseToken = \"4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z\";",
				"ClickHouseToken = \"4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z\"",
				"ClickHouse_token: '4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z'",
				"String ClickHouseToken = \"4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z\";",
				"var ClickHouseToken = \"4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z\"",
				"$ClickHouseToken .= \"4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z\"",
				"ClickHouse_TOKEN ::= \"4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z\"",
				"ClickHouse_TOKEN ?= \"4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z\"",
				"{\"config.ini\": \"CLICKHOUSE_TOKEN=4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z\\nBACKUP_ENABLED=true\"}",
				"ClickHouse_token: \"4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z\"",
				"var ClickHouseToken string = \"4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z\"",
				"System.setProperty(\"CLICKHOUSE_TOKEN\", \"4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z\")",
				"  \"ClickHouseToken\" => \"4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z\"",
				"ClickHouse_TOKEN := \"4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z\"",
				"ClickHouse_TOKEN :::= \"4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z\"",
				"ClickHouseToken=4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z",
				"ClickHouseToken := \"4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z\"",
				"ClickHouseToken := `4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z`",
				"ClickHouseToken = '4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z'",
				"ClickHouse_TOKEN = \"4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z\"",
				"ClickHouseToken=\"4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z\"",
				"ClickHouseToken = \"4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z\"",
				"ClickHouseToken = 4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z",
				"{\n    \"ClickHouse_token\": \"4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z\"\n}",
				"<ClickHouseToken>\n    4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z\n</ClickHouseToken>",
				"ClickHouseToken = '4b1dljOfXJMuD2S4GV3UM1tEk2DB6xwwCyPBgTRwrq'",
				"ClickHouse_TOKEN ::= \"4b1dljOfXJMuD2S4GV3UM1tEk2DB6xwwCyPBgTRwrq\"",
				"ClickHouseToken = 4b1dljOfXJMuD2S4GV3UM1tEk2DB6xwwCyPBgTRwrq",
				"ClickHouse_token: '4b1dljOfXJMuD2S4GV3UM1tEk2DB6xwwCyPBgTRwrq'",
				"ClickHouse_token: \"4b1dljOfXJMuD2S4GV3UM1tEk2DB6xwwCyPBgTRwrq\"",
				"var ClickHouseToken string = \"4b1dljOfXJMuD2S4GV3UM1tEk2DB6xwwCyPBgTRwrq\"",
				"ClickHouseToken = \"4b1dljOfXJMuD2S4GV3UM1tEk2DB6xwwCyPBgTRwrq\"",
				"System.setProperty(\"CLICKHOUSE_TOKEN\", \"4b1dljOfXJMuD2S4GV3UM1tEk2DB6xwwCyPBgTRwrq\")",
				"ClickHouse_TOKEN :::= \"4b1dljOfXJMuD2S4GV3UM1tEk2DB6xwwCyPBgTRwrq\"",
				"ClickHouseToken=4b1dljOfXJMuD2S4GV3UM1tEk2DB6xwwCyPBgTRwrq",
				"{\n    \"ClickHouse_token\": \"4b1dljOfXJMuD2S4GV3UM1tEk2DB6xwwCyPBgTRwrq\"\n}",
				"ClickHouse_token: 4b1dljOfXJMuD2S4GV3UM1tEk2DB6xwwCyPBgTRwrq",
				"ClickHouseToken := \"4b1dljOfXJMuD2S4GV3UM1tEk2DB6xwwCyPBgTRwrq\"",
				"String ClickHouseToken = \"4b1dljOfXJMuD2S4GV3UM1tEk2DB6xwwCyPBgTRwrq\";",
				"$ClickHouseToken .= \"4b1dljOfXJMuD2S4GV3UM1tEk2DB6xwwCyPBgTRwrq\"",
				"  \"ClickHouseToken\" => \"4b1dljOfXJMuD2S4GV3UM1tEk2DB6xwwCyPBgTRwrq\"",
				"ClickHouse_TOKEN ?= \"4b1dljOfXJMuD2S4GV3UM1tEk2DB6xwwCyPBgTRwrq\"",
				"ClickHouseToken=\"4b1dljOfXJMuD2S4GV3UM1tEk2DB6xwwCyPBgTRwrq\"",
				"{\"config.ini\": \"CLICKHOUSE_TOKEN=4b1dljOfXJMuD2S4GV3UM1tEk2DB6xwwCyPBgTRwrq\\nBACKUP_ENABLED=true\"}",
				"var ClickHouseToken = \"4b1dljOfXJMuD2S4GV3UM1tEk2DB6xwwCyPBgTRwrq\"",
				"ClickHouse_TOKEN = \"4b1dljOfXJMuD2S4GV3UM1tEk2DB6xwwCyPBgTRwrq\"",
				"ClickHouse_TOKEN := \"4b1dljOfXJMuD2S4GV3UM1tEk2DB6xwwCyPBgTRwrq\"",
				"ClickHouseToken = \"4b1dljOfXJMuD2S4GV3UM1tEk2DB6xwwCyPBgTRwrq\"",
				"<ClickHouseToken>\n    4b1dljOfXJMuD2S4GV3UM1tEk2DB6xwwCyPBgTRwrq\n</ClickHouseToken>",
				"string ClickHouseToken = \"4b1dljOfXJMuD2S4GV3UM1tEk2DB6xwwCyPBgTRwrq\";",
				"ClickHouseToken := `4b1dljOfXJMuD2S4GV3UM1tEk2DB6xwwCyPBgTRwrq`",
			},
			falsePositives: []string{
				`key = 4b1dXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`,    // Low entropy
				`key = adf4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z`, // Not start of a word
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tps := utils.GenerateSampleSecrets("ClickHouse", "4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z")
			tps = append(tps, utils.GenerateSampleSecrets("ClickHouse", "4b1d"+secrets.NewSecret("[A-Za-z0-9]{38}"))...)

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
			rule := ConvertNewRuleToGitleaksRule(ClickhouseCloudApiSecretKey())
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
