package resources

import "github.com/checkmarx/2ms/v4/engine/rules/ruledefine"

type ScanConfig struct {
	IgnoreResultIds []string
	SelectRules     []string
	IgnoreRules     []string
	CustomRules     []*ruledefine.Rule
	WithValidation  bool
	PluginName      string
}
