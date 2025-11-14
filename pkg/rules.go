package scanner

import (
	"github.com/checkmarx/2ms/v4/engine/rules"
	"github.com/checkmarx/2ms/v4/engine/rules/ruledefine"
)

func GetDefaultRules(includeDeprecated bool) []*ruledefine.Rule {
	return rules.GetDefaultRules(includeDeprecated)
}
