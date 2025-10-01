package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var GrafanaServiceAccountTokenRegex = utils.GenerateUniqueTokenRegex(`glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}`, true)

func GrafanaServiceAccountToken() *NewRule {
	return &NewRule{
		BaseRuleID:  "60b6a2aa-2eaf-4a3d-bd3c-6d5f6274b4fc",
		Description: "Discovered a Grafana service account token, posing a risk of compromised monitoring services and data integrity.",
		RuleID:      "grafana-service-account-token",
		Regex:       GrafanaServiceAccountTokenRegex,
		Entropy:     3,
		Keywords:    []string{"glsa_"},
		Severity:    "High",
	}
}
