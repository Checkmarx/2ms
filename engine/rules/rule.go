package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

type ScoreParameters struct {
	Category RuleCategory
	RuleType uint8
}

type Rule struct {
	Rule            config.Rule
	Tags            []string
	ScoreParameters ScoreParameters
}
