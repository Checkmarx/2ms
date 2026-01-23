package resources

import "github.com/checkmarx/2ms/v5/engine/rules/ruledefine"

type ScanConfig struct {
	IgnoreResultIds []string
	SelectRules     []string
	IgnoreRules     []string
	CustomRules     []*ruledefine.Rule
	WithValidation  bool
	PluginName      string

	// Limit settings
	MaxFindings               uint64 // Total findings limit across entire scan (0 = no limit)
	MaxRuleMatchesPerFragment uint64 // Regex matches limit per rule per fragment (0 = no limit)
	MaxSecretSize             uint64 // Maximum secret size in bytes (0 = no limit)
}
