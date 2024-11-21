package engine

import (
	"crypto/sha1"
	"fmt"
	"github.com/checkmarx/2ms/engine/score"
	"os"
	"regexp"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/checkmarx/2ms/engine/rules"
	"github.com/checkmarx/2ms/engine/validation"
	"github.com/checkmarx/2ms/lib/secrets"
	"github.com/checkmarx/2ms/plugins"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

type Engine struct {
	rules              map[string]config.Rule
	rulesBaseRiskScore map[string]float64
	detector           detect.Detector
	validator          validation.Validator

	ignoredIds    []string
	allowedValues []string
}

const customRegexRuleIdFormat = "custom-regex-%d"

type EngineConfig struct {
	SelectedList []string
	IgnoreList   []string
	SpecialList  []string

	MaxTargetMegabytes int

	IgnoredIds    []string
	AllowedValues []string
}

func Init(engineConfig EngineConfig) (*Engine, error) {
	selectedRules := rules.FilterRules(engineConfig.SelectedList, engineConfig.IgnoreList, engineConfig.SpecialList)
	if len(*selectedRules) == 0 {
		return nil, fmt.Errorf("no rules were selected")
	}

	rulesToBeApplied := make(map[string]config.Rule)
	rulesBaseRiskScore := make(map[string]float64)
	keywords := []string{}
	for _, rule := range *selectedRules {
		rulesToBeApplied[rule.Rule.RuleID] = rule.Rule
		rulesBaseRiskScore[rule.Rule.RuleID] = score.GetBaseRiskScore(rule.ScoreParameters.Category, rule.ScoreParameters.RuleType)
		for _, keyword := range rule.Rule.Keywords {
			keywords = append(keywords, strings.ToLower(keyword))
		}
	}
	cfg.Rules = rulesToBeApplied
	cfg.Keywords = keywords

	detector := detect.NewDetector(cfg)
	detector.MaxTargetMegaBytes = engineConfig.MaxTargetMegabytes

	return &Engine{
		rules:              rulesToBeApplied,
		rulesBaseRiskScore: rulesBaseRiskScore,
		detector:           *detector,
		validator:          *validation.NewValidator(),

		ignoredIds:    engineConfig.IgnoredIds,
		allowedValues: engineConfig.AllowedValues,
	}, nil
}

func (e *Engine) Detect(item plugins.ISourceItem, secretsChannel chan *secrets.Secret, wg *sync.WaitGroup, pluginName string) {
	defer wg.Done()

	fragment := detect.Fragment{
		Raw:      *item.GetContent(),
		FilePath: item.GetSource(),
	}
	for _, value := range e.detector.Detect(fragment) {
		itemId := getFindingId(item, value)
		var startLine, endLine int
		if pluginName == "filesystem" {
			startLine = value.StartLine + 1
			endLine = value.EndLine + 1
		} else {
			startLine = value.StartLine
			endLine = value.EndLine
		}
		secret := &secrets.Secret{
			ID:              itemId,
			Source:          item.GetSource(),
			RuleID:          value.RuleID,
			StartLine:       startLine,
			StartColumn:     value.StartColumn,
			EndLine:         endLine,
			EndColumn:       value.EndColumn,
			Value:           value.Secret,
			LineContent:     value.Line,
			RuleDescription: value.Description,
		}
		if !isSecretIgnored(secret, &e.ignoredIds, &e.allowedValues) {
			secretsChannel <- secret
		} else {
			log.Debug().Msgf("Secret %s was ignored", secret.ID)
		}
	}
}

func (e *Engine) AddRegexRules(patterns []string) error {
	for idx, pattern := range patterns {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("failed to compile regex rule %s: %w", pattern, err)
		}
		rule := config.Rule{
			Description: "Custom Regex Rule From User",
			RuleID:      fmt.Sprintf(customRegexRuleIdFormat, idx+1),
			Regex:       regex,
			Keywords:    []string{},
		}
		e.rules[rule.RuleID] = rule
	}
	return nil
}

func (s *Engine) RegisterForValidation(secret *secrets.Secret) {
	s.validator.RegisterForValidation(secret)
}

func (s *Engine) Score(secret *secrets.Secret, validateFlag bool, wg *sync.WaitGroup) {
	defer wg.Done()
	validationStatus := secrets.UnknownResult // default validity
	if validateFlag {
		validationStatus = secret.ValidationStatus
	}
	secret.CvssScore = score.GetCvssScore(s.GetRuleBaseRiskScore(secret.RuleID), validationStatus)
}

func (s *Engine) Validate() {
	s.validator.Validate()
}

func getFindingId(item plugins.ISourceItem, finding report.Finding) string {
	idParts := []string{item.GetID(), finding.RuleID, finding.Secret}
	sha := sha1.Sum([]byte(strings.Join(idParts, "-")))
	return fmt.Sprintf("%x", sha)
}

func isSecretIgnored(secret *secrets.Secret, ignoredIds, allowedValues *[]string) bool {
	for _, allowedValue := range *allowedValues {
		if secret.Value == allowedValue {
			return true
		}
	}
	for _, ignoredId := range *ignoredIds {
		if secret.ID == ignoredId {
			return true
		}
	}
	return false
}

func GetRulesCommand(engineConfig *EngineConfig) *cobra.Command {
	canValidateDisplay := map[bool]string{
		true:  "V",
		false: "",
	}

	return &cobra.Command{
		Use:   "rules",
		Short: "List all rules",
		Long:  `List all rules`,
		RunE: func(cmd *cobra.Command, args []string) error {

			rules := rules.FilterRules(engineConfig.SelectedList, engineConfig.IgnoreList, engineConfig.SpecialList)

			tab := tabwriter.NewWriter(os.Stdout, 1, 2, 2, ' ', 0)

			fmt.Fprintln(tab, "Name\tDescription\tTags\tValidity Check")
			fmt.Fprintln(tab, "----\t----\t----\t----")
			for _, rule := range *rules {
				fmt.Fprintf(
					tab,
					"%s\t%s\t%s\t%s\n",
					rule.Rule.RuleID,
					rule.Rule.Description,
					strings.Join(rule.Tags, ","),
					canValidateDisplay[validation.IsCanValidateRule(rule.Rule.RuleID)],
				)
			}
			if err := tab.Flush(); err != nil {
				return err
			}

			return nil
		},
	}
}

func (s *Engine) GetRuleBaseRiskScore(ruleId string) float64 {
	return s.rulesBaseRiskScore[ruleId]
}
