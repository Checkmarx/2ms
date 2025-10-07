package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var ClickhouseCloudApiSecretKeyRegex = regexp.MustCompile(`\b(4b1d[A-Za-z0-9]{38})\b`)

func ClickHouseCloud() *NewRule {
	return &NewRule{
		BaseRuleID: "cc6ac965-1701-486d-858e-0179d15d3429",
		Description: "Identified a pattern that may indicate clickhouse cloud API secret key," +
			" risking unauthorized clickhouse cloud api access and data breaches on ClickHouse Cloud platforms.",
		RuleID:  "clickhouse-cloud-api-secret-key",
		Regex:   ClickhouseCloudApiSecretKeyRegex,
		Entropy: 3,
		Keywords: []string{
			"4b1d",
		},
		Severity:        "High",
		Tags:            []string{TagSecretKey},
		ScoreParameters: ScoreParameters{Category: CategoryCloudPlatform, RuleType: 4},
	}
}
