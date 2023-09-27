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
	"github.com/checkmarx/2ms/reporting"
	"github.com/checkmarx/2ms/secrets/rules"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

type Secrets struct {
	rules    map[string]config.Rule
	detector detect.Detector
}

const customRegexRuleIdFormat = "custom-regex-%d"

func Init(selectedList, ignoreList, specialList []string) (*Secrets, error) {
	selectedRules := rules.FilterRules(selectedList, ignoreList, specialList)
	if len(*selectedRules) == 0 {
		return nil, fmt.Errorf("no rules were selected")
	}

	rulesToBeApplied := make(map[string]config.Rule)
	for _, rule := range *selectedRules {
		// required to be empty when not running via cli. otherwise rule will be ignored
		rule.Rule.Keywords = []string{}
		rulesToBeApplied[rule.Rule.RuleID] = rule.Rule
	}

	config := config.Config{
		Rules: rulesToBeApplied,
	}

	detector := detect.NewDetector(config)

	return &Secrets{
		rules:    rulesToBeApplied,
		detector: *detector,
	}, nil
}

func (s *Secrets) Detect(item plugins.Item, secretsChannel chan reporting.Secret, wg *sync.WaitGroup, ignoredIds []string) {
	defer wg.Done()

	fragment := detect.Fragment{
		Raw: item.Content,
	}
	for _, value := range s.detector.Detect(fragment) {
		itemId := getFindingId(item, value)
		secret := reporting.Secret{
			ID:          itemId,
			Source:      item.Source,
			RuleID:      value.RuleID,
			StartLine:   value.StartLine,
			StartColumn: value.StartColumn,
			EndLine:     value.EndLine,
			EndColumn:   value.EndColumn,
			Value:       value.Secret,
		}
		if !isSecretIgnored(&secret, &ignoredIds) {
			secretsChannel <- secret
		} else {
			log.Debug().Msgf("Secret %s was ignored", secret.ID)
		}
	}
}

func (s *Secrets) AddRegexRules(patterns []string) error {
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

func isSecretIgnored(secret *reporting.Secret, ignoredIds *[]string) bool {
	for _, ignoredId := range *ignoredIds {
		if secret.ID == ignoredId {
			return true
		}
	}
	return false
}

func GetRulesCommand(selectedList, ignoreList, specialList *[]string) *cobra.Command {
	return &cobra.Command{
		Use:   "rules",
		Short: "List all rules",
		Long:  `List all rules`,
		RunE: func(cmd *cobra.Command, args []string) error {

			rules := rules.FilterRules(*selectedList, *ignoreList, *specialList)

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
