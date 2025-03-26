package rules

import (
	"strings"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/base"
	"github.com/zricethezav/gitleaks/v8/logging"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
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

// Copied from https://github.com/gitleaks/gitleaks/blob/463d24618fa42fc7629dc30c9744ebe36c5df1ab/cmd/generate/config/rules/rule.go
func validate(rule config.Rule, truePositives []string, falsePositives []string) *config.Rule {
	r := &rule
	d := createSingleRuleDetector(r)

	for _, tp := range truePositives {
		if len(d.DetectString(tp)) < 1 {
			logging.Fatal().
				Str("rule", r.RuleID).
				Str("value", tp).
				Str("regex", r.Regex.String()).
				Msg("Failed to Validate. True positive was not detected by regex.")
		}
	}
	for _, fp := range falsePositives {
		findings := d.DetectString(fp)
		if len(findings) != 0 {
			logging.Fatal().
				Str("rule", r.RuleID).
				Str("value", fp).
				Str("regex", r.Regex.String()).
				Msg("Failed to Validate. False positive was detected by regex.")
		}
	}
	return r
}

func createSingleRuleDetector(r *config.Rule) *detect.Detector {
	// normalize keywords like in the config package
	var (
		uniqueKeywords = make(map[string]struct{})
		keywords       []string
	)
	for _, keyword := range r.Keywords {
		k := strings.ToLower(keyword)
		if _, ok := uniqueKeywords[k]; ok {
			continue
		}
		keywords = append(keywords, k)
		uniqueKeywords[k] = struct{}{}
	}
	r.Keywords = keywords

	rules := map[string]config.Rule{
		r.RuleID: *r,
	}
	cfg := base.CreateGlobalConfig()
	cfg.Rules = rules
	cfg.Keywords = uniqueKeywords
	return detect.NewDetector(cfg)
}
