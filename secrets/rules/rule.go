package rules

import (
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

type Rule struct {
	Rule config.Rule
	Tags []string
}

// Copied from https://github.com/gitleaks/gitleaks/blob/463d24618fa42fc7629dc30c9744ebe36c5df1ab/cmd/generate/config/rules/rule.go
func validate(r config.Rule, truePositives []string, falsePositives []string) *config.Rule {
	// normalize keywords like in the config package
	var keywords []string
	for _, k := range r.Keywords {
		keywords = append(keywords, strings.ToLower(k))
	}
	r.Keywords = keywords

	rules := make(map[string]config.Rule)
	rules[r.RuleID] = r
	d := detect.NewDetector(config.Config{
		Rules:    rules,
		Keywords: keywords,
	})
	for _, tp := range truePositives {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msgf("Failed to validate. For rule ID [%s], true positive [%s] was not detected by regexp [%s]", r.RuleID, tp, r.Regex) // lint:ignore This Fatal happens in a test
		}
	}
	for _, fp := range falsePositives {
		if len(d.DetectString(fp)) != 0 {
			log.Fatal().Msgf("Failed to validate. For rule ID [%s], false positive [%s] was detected by regexp [%s]", r.RuleID, fp, r.Regex) // lint:ignore This Fatal happens in a test
		}
	}
	return &r
}
