package rules

import (
	"strings"

	"github.com/rs/zerolog/log"
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
func validate(r config.Rule, truePositives []string, falsePositives []string) *config.Rule { //nolint:gocritic // hugeParam: r needed
	// normalize keywords like in the config package
	var keywords []string
	for _, k := range r.Keywords {
		keywords = append(keywords, strings.ToLower(k))
	}
	r.Keywords = keywords

	detectorKeywords := make(map[string]struct{})
	for _, k := range keywords {
		detectorKeywords[k] = struct{}{}
	}

	rules := make(map[string]config.Rule)
	rules[r.RuleID] = r
	d := detect.NewDetector(config.Config{
		Rules:    rules,
		Keywords: detectorKeywords,
	})
	for _, tp := range truePositives {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal(). // lint:ignore This Fatal happens in a test
					Str("rule", r.RuleID).
					Str("value", tp).
					Str("regex", r.Regex.String()).
					Msg("Failed to Validate. True positive was not detected by regex.")
		}
	}
	for _, fp := range falsePositives {
		if len(d.DetectString(fp)) != 0 {
			log.Fatal(). // lint:ignore This Fatal happens in a test
					Str("rule", r.RuleID).
					Str("value", fp).
					Str("regex", r.Regex.String()).
					Msg("Failed to Validate. False positive was detected by regex.")
		}
	}
	return &r
}
