package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSumoLogicAccessIDToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "SumoLogicAccessID validation",
			truePositives: []string{
				"System.setProperty(\"SUMO_TOKEN\", \"suskUE6VWx3py5\")",
				"sumo_TOKEN ::= \"suskUE6VWx3py5\"",
				"sumoToken=suskUE6VWx3py5",
				"{\"config.ini\": \"SUMO_TOKEN=suskUE6VWx3py5\\nBACKUP_ENABLED=true\"}",
				"string sumoToken = \"suskUE6VWx3py5\";",
				"sumo_TOKEN ?= \"suskUE6VWx3py5\"",
				"{\n    \"sumo_token\": \"suskUE6VWx3py5\"\n}",
				"<sumoToken>\n    suskUE6VWx3py5\n</sumoToken>",
				"var sumoToken string = \"suskUE6VWx3py5\"",
				"var sumoToken = \"suskUE6VWx3py5\"",
				"$sumoToken .= \"suskUE6VWx3py5\"",
				"sumo_TOKEN :::= \"suskUE6VWx3py5\"",
				"sumo_token: suskUE6VWx3py5",
				"sumo_token: 'suskUE6VWx3py5'",
				"sumoToken := `suskUE6VWx3py5`",
				"String sumoToken = \"suskUE6VWx3py5\";",
				"sumoToken = \"suskUE6VWx3py5\"",
				"  \"sumoToken\" => \"suskUE6VWx3py5\"",
				"sumo_TOKEN = \"suskUE6VWx3py5\"",
				"sumo_TOKEN := \"suskUE6VWx3py5\"",
				"sumoToken=\"suskUE6VWx3py5\"",
				"sumoToken = \"suskUE6VWx3py5\"",
				"sumoToken = suskUE6VWx3py5",
				"sumo_token: \"suskUE6VWx3py5\"",
				"sumoToken := \"suskUE6VWx3py5\"",
				"sumoToken = 'suskUE6VWx3py5'",
				"sumologic.accessId = \"su9OL59biWiJu7\"",
				"sumologic_access_id = \"sug5XpdpaoxtOH\"",
				"export SUMOLOGIC_ACCESSID=\"suDbJw97o9WVo0\"",
				"SUMO_ACCESS_ID = \"suGyI5imvADdvU\"",
			},
			falsePositives: []string{
				`- (NSNumber *)sumOfProperty:(NSString *)property;`,
				`- (NSInteger)sumOfValuesInRange:(NSRange)range;`,
				`+ (unsigned char)byteChecksumOfData:(id)arg1;`,
				`sumOfExposures = sumOfExposures;`, // gitleaks:allow
				`.si-sumologic.si--color::before { color: #000099; }`,
				`/// Based on the SumoLogic keyword syntax:`,
				`sumologic_access_id         = ""`,
				`SUMOLOGIC_ACCESSID: ${SUMOLOGIC_ACCESSID}`,
				`export SUMOLOGIC_ACCESSID=XXXXXXXXXXXXXX`, // gitleaks:allow
				`sumObj = suGyI5imvADdvU`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(SumoLogicAccessID())
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
