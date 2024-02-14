package secrets

import (
	"crypto/sha1"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/checkmarx/2ms/plugins"
	"github.com/checkmarx/2ms/secrets/rules"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

type Engine struct {
	rules    map[string]config.Rule
	detector detect.Detector
}

const customRegexRuleIdFormat = "custom-regex-%d"

type SecretsConfig struct {
	SelectedList []string
	IgnoreList   []string
	SpecialList  []string

	MaxTargetMegabytes int
}

func Init(secretsConfig SecretsConfig) (*Engine, error) {
	selectedRules := rules.FilterRules(secretsConfig.SelectedList, secretsConfig.IgnoreList, secretsConfig.SpecialList)
	if len(*selectedRules) == 0 {
		return nil, fmt.Errorf("no rules were selected")
	}

	rulesToBeApplied := make(map[string]config.Rule)
	for _, rule := range *selectedRules {
		// required to be empty when not running via cli. otherwise rule will be ignored
		rule.Rule.Keywords = []string{}
		rulesToBeApplied[rule.Rule.RuleID] = rule.Rule
	}

	detector := detect.NewDetector(config.Config{
		Rules: rulesToBeApplied,
	})
	detector.MaxTargetMegaBytes = secretsConfig.MaxTargetMegabytes

	return &Engine{
		rules:    rulesToBeApplied,
		detector: *detector,
	}, nil
}

func (s *Engine) Detect(item plugins.Item, secretsChannel chan *Secret, wg *sync.WaitGroup, ignoredIds []string) {
	defer wg.Done()

	fragment := detect.Fragment{
		Raw: item.Content,
	}
	for _, value := range s.detector.Detect(fragment) {
		itemId := getFindingId(item, value)
		secret := &Secret{
			ID:          itemId,
			Source:      item.Source,
			RuleID:      value.RuleID,
			StartLine:   value.StartLine,
			StartColumn: value.StartColumn,
			EndLine:     value.EndLine,
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

func getFindingId(item plugins.Item, finding report.Finding) string {
	idParts := []string{item.ID, finding.RuleID, finding.Secret}
	sha := sha1.Sum([]byte(strings.Join(idParts, "-")))
	return fmt.Sprintf("%x", sha)
}

func isSecretIgnored(secret *Secret, ignoredIds *[]string) bool {
	for _, ignoredId := range *ignoredIds {
		if secret.ID == ignoredId {
			return true
		}
	}
	return false
}

func GetRulesCommand(secretsConfig *SecretsConfig) *cobra.Command {
	return &cobra.Command{
		Use:   "rules",
		Short: "List all rules",
		Long:  `List all rules`,
		RunE: func(cmd *cobra.Command, args []string) error {

			rules := rules.FilterRules(secretsConfig.SelectedList, secretsConfig.IgnoreList, secretsConfig.SpecialList)

			tab := tabwriter.NewWriter(os.Stdout, 1, 2, 2, ' ', 0)

			fmt.Fprintln(tab, "Name\tDescription\tTags")
			fmt.Fprintln(tab, "----\t----\t----")
			for _, rule := range *rules {
				fmt.Fprintf(tab, "%s\t%s\t%s\n", rule.Rule.RuleID, rule.Rule.Description, strings.Join(rule.Tags, ","))
			}
			if err := tab.Flush(); err != nil {
				return err
			}

			return nil
		},
	}
}
