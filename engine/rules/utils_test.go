package rules

import (
	"strings"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/base"
	gitleaksrule "github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/logging"
)

func createSingleRuleDetector(r *gitleaksrule.Rule) *detect.Detector {
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

	rules := map[string]gitleaksrule.Rule{
		r.RuleID: *r,
	}
	cfg := base.CreateGlobalConfig()
	cfg.Rules = rules
	cfg.Keywords = uniqueKeywords
	for _, a := range cfg.Allowlists {
		if err := a.Validate(); err != nil {
			logging.Fatal().Err(err).Msg("invalid global allowlist")
		}
	}
	return detect.NewDetector(cfg)
}
