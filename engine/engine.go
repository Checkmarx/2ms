package engine

import (
	"crypto/sha1"
	"fmt"
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
	rules     map[string]config.Rule
	detector  detect.Detector
	validator validation.Validator
}

const customRegexRuleIdFormat = "custom-regex-%d"

type EngineConfig struct {
	SelectedList []string
	IgnoreList   []string
	SpecialList  []string

	MaxTargetMegabytes int
}

func Init(engineConfig EngineConfig) (*Engine, error) {
	selectedRules := rules.FilterRules(engineConfig.SelectedList, engineConfig.IgnoreList, engineConfig.SpecialList)
	if len(*selectedRules) == 0 {
		return nil, fmt.Errorf("no rules were selected")
	}

	rulesToBeApplied := make(map[string]config.Rule)
	for _, rule := range *selectedRules {
		// required to be empty when not running via cli. otherwise rule will be ignored
		rule.Rule.Keywords = []string{}
		rulesToBeApplied[rule.Rule.RuleID] = rule.Rule
	}
	cfg.Rules = rulesToBeApplied

	detector := detect.NewDetector(cfg)
	detector.MaxTargetMegaBytes = engineConfig.MaxTargetMegabytes

	return &Engine{
		rules:     rulesToBeApplied,
		detector:  *detector,
		validator: *validation.NewValidator(),
	}, nil
}

func (s *Engine) Detect(item plugins.ISourceItem, secretsChannel chan *secrets.Secret, wg *sync.WaitGroup, ignoredIds []string, pluginName string) {
	defer wg.Done()

	fragment := detect.Fragment{
		Raw:      *item.GetContent(),
		FilePath: item.GetSource(),
	}
	for _, value := range s.detector.Detect(fragment) {
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
			ID:          itemId,
			Source:      item.GetSource(),
			RuleID:      value.RuleID,
			StartLine:   startLine,
			StartColumn: value.StartColumn,
			EndLine:     endLine,
			EndColumn:   value.EndColumn,
			Value:       value.Secret,
		}
		if !isSecretIgnored(secret, &ignoredIds) {
			secretsChannel <- secret
		} else {
			log.Debug().Msgf("Secret %s was ignored", secret.ID)
		}
	}
}

func (s *Engine) AddRegexRules(patterns []string) error {
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
		s.rules[rule.RuleID] = rule
	}
	return nil
}

func (s *Engine) RegisterForValidation(secret *secrets.Secret, wg *sync.WaitGroup) {
	defer wg.Done()
	s.validator.RegisterForValidation(secret)
}

func (s *Engine) Validate() {
	s.validator.Validate()
}

func getFindingId(item plugins.ISourceItem, finding report.Finding) string {
	idParts := []string{item.GetID(), finding.RuleID, finding.Secret}
	sha := sha1.Sum([]byte(strings.Join(idParts, "-")))
	return fmt.Sprintf("%x", sha)
}

func isSecretIgnored(secret *secrets.Secret, ignoredIds *[]string) bool {
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
