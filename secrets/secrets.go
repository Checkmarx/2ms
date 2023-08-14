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
	secrets "github.com/checkmarx/2ms/secrets/rules"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/rules"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

type Secrets struct {
	rules    map[string]config.Rule
	detector detect.Detector
}

type Rule struct {
	Rule config.Rule
	Tags []string
}

const TagApiKey = "api-key"
const TagClientId = "client-id"
const TagClientSecret = "client-secret"
const TagSecretKey = "secret-key"
const TagAccessKey = "access-key"
const TagAccessId = "access-id"
const TagApiToken = "api-token"
const TagAccessToken = "access-token"
const TagRefreshToken = "refresh-token"
const TagPrivateKey = "private-key"
const TagPublicKey = "public-key"
const TagEncryptionKey = "encryption-key"
const TagTriggerToken = "trigger-token"
const TagRegistrationToken = "registration-token"
const TagPassword = "password"
const TagUploadToken = "upload-token"
const TagPublicSecret = "public-secret"
const TagSensitiveUrl = "sensitive-url"
const TagWebhook = "webhook"

const customRegexRuleIdFormat = "custom-regex-%d"

func Init(includeList, excludeList []string) (*Secrets, error) {
	if len(includeList) > 0 && len(excludeList) > 0 {
		return nil, fmt.Errorf("cannot use both include and exclude flags")
	}

	allRules, _ := loadAllRules()
	rulesToBeApplied := make(map[string]config.Rule)
	if len(includeList) > 0 {
		rulesToBeApplied = selectRules(allRules, includeList)
	} else if len(excludeList) > 0 {
		rulesToBeApplied = excludeRules(allRules, excludeList)
	} else {
		for _, rule := range allRules {
			// required to be empty when not running via cli. otherwise rule will be ignored
			rule.Rule.Keywords = []string{}
			rulesToBeApplied[rule.Rule.RuleID] = rule.Rule
		}
	}
	if len(rulesToBeApplied) == 0 {
		return nil, fmt.Errorf("no rules were selected")
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

func selectRules(allRules []Rule, tags []string) map[string]config.Rule {
	rulesToBeApplied := make(map[string]config.Rule)

	for _, rule := range allRules {
		if isRuleMatch(rule, tags) {
			// required to be empty when not running via cli. otherwise rule will be ignored
			rule.Rule.Keywords = []string{}
			rulesToBeApplied[rule.Rule.RuleID] = rule.Rule
		}
	}
	return rulesToBeApplied
}

func excludeRules(allRules []Rule, tags []string) map[string]config.Rule {
	rulesToBeApplied := make(map[string]config.Rule)

	for _, rule := range allRules {
		if !isRuleMatch(rule, tags) {
			// required to be empty when not running via cli. otherwise rule will be ignored
			rule.Rule.Keywords = []string{}
			rulesToBeApplied[rule.Rule.RuleID] = rule.Rule
		}
	}
	return rulesToBeApplied
}

func isRuleMatch(rule Rule, tags []string) bool {
	for _, tag := range tags {
		if strings.EqualFold(rule.Rule.RuleID, tag) {
			return true
		}
		for _, ruleTag := range rule.Tags {
			if strings.EqualFold(ruleTag, tag) {
				return true
			}
		}
	}
	return false
}

func getRules(allRules []Rule, tags []string) map[string]config.Rule {
	rulesToBeApplied := make(map[string]config.Rule)

	if isAllFilter(tags) {
		// ensure rules have unique ids
		for _, rule := range allRules {
			// required to be empty when not running via cli. otherwise rule will be ignored
			rule.Rule.Keywords = []string{}
			rulesToBeApplied[rule.Rule.RuleID] = rule.Rule
		}
	} else {
		for _, rule := range allRules {
			rule.Rule.Keywords = []string{}
			for _, userTag := range tags {
				for _, ruleTag := range rule.Tags {
					if strings.EqualFold(ruleTag, userTag) {
						rulesToBeApplied[rule.Rule.RuleID] = rule.Rule
					}
				}
			}
		}
	}
	return rulesToBeApplied
}

func isAllFilter(rulesFilter []string) bool {
	for _, filter := range rulesFilter {
		if strings.EqualFold(filter, "all") {
			return true
		}
	}
	return false
}

func loadAllRules() ([]Rule, error) {
	var allRules []Rule
	allRules = make([]Rule, 0)

	allRules = append(allRules, Rule{Rule: *rules.AdafruitAPIKey(), Tags: []string{TagApiKey}})
	allRules = append(allRules, Rule{Rule: *rules.AdobeClientID(), Tags: []string{TagClientId}})
	allRules = append(allRules, Rule{Rule: *rules.AdobeClientSecret(), Tags: []string{TagClientSecret}})
	allRules = append(allRules, Rule{Rule: *rules.AgeSecretKey(), Tags: []string{TagSecretKey}})
	allRules = append(allRules, Rule{Rule: *rules.Airtable(), Tags: []string{TagApiKey}})
	allRules = append(allRules, Rule{Rule: *rules.AlgoliaApiKey(), Tags: []string{TagApiKey}})
	allRules = append(allRules, Rule{Rule: *rules.AlibabaAccessKey(), Tags: []string{TagAccessKey, TagAccessId}})
	allRules = append(allRules, Rule{Rule: *rules.AlibabaSecretKey(), Tags: []string{TagSecretKey}})
	allRules = append(allRules, Rule{Rule: *rules.AsanaClientID(), Tags: []string{TagClientId}})
	allRules = append(allRules, Rule{Rule: *rules.AsanaClientSecret(), Tags: []string{TagClientSecret}})
	allRules = append(allRules, Rule{Rule: *rules.Atlassian(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.AWS(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.BitBucketClientID(), Tags: []string{TagClientId}})
	allRules = append(allRules, Rule{Rule: *rules.BitBucketClientSecret(), Tags: []string{TagClientSecret}})
	allRules = append(allRules, Rule{Rule: *rules.BittrexAccessKey(), Tags: []string{TagAccessKey}})
	allRules = append(allRules, Rule{Rule: *rules.BittrexSecretKey(), Tags: []string{TagSecretKey}})
	allRules = append(allRules, Rule{Rule: *rules.Beamer(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.CodecovAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.CoinbaseAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.Clojars(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.ConfluentAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.ConfluentSecretKey(), Tags: []string{TagSecretKey}})
	allRules = append(allRules, Rule{Rule: *rules.Contentful(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.Databricks(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.DatadogtokenAccessToken(), Tags: []string{TagAccessToken, TagClientId}})
	allRules = append(allRules, Rule{Rule: *rules.DigitalOceanPAT(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.DigitalOceanOAuthToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.DigitalOceanRefreshToken(), Tags: []string{TagRefreshToken}})
	allRules = append(allRules, Rule{Rule: *rules.DiscordAPIToken(), Tags: []string{TagApiKey, TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.DiscordClientID(), Tags: []string{TagClientId}})
	allRules = append(allRules, Rule{Rule: *rules.DiscordClientSecret(), Tags: []string{TagClientSecret}})
	allRules = append(allRules, Rule{Rule: *rules.Doppler(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.DropBoxAPISecret(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.DropBoxShortLivedAPIToken(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.DropBoxLongLivedAPIToken(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.DroneciAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.Duffel(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.Dynatrace(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.EasyPost(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.EasyPostTestAPI(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.EtsyAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.Facebook(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.FastlyAPIToken(), Tags: []string{TagApiToken, TagApiKey}})
	allRules = append(allRules, Rule{Rule: *rules.FinicityClientSecret(), Tags: []string{TagClientSecret}})
	allRules = append(allRules, Rule{Rule: *rules.FinicityAPIToken(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.FlickrAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.FinnhubAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.FlutterwavePublicKey(), Tags: []string{TagPublicKey}})
	allRules = append(allRules, Rule{Rule: *rules.FlutterwaveSecretKey(), Tags: []string{TagSecretKey}})
	allRules = append(allRules, Rule{Rule: *rules.FlutterwaveEncKey(), Tags: []string{TagEncryptionKey}})
	allRules = append(allRules, Rule{Rule: *rules.FrameIO(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.FreshbooksAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.GCPAPIKey(), Tags: []string{TagApiKey}})
	allRules = append(allRules, Rule{Rule: *rules.GenericCredential(), Tags: []string{TagApiKey}})
	allRules = append(allRules, Rule{Rule: *rules.GitHubPat(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.GitHubFineGrainedPat(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.GitHubOauth(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.GitHubApp(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.GitHubRefresh(), Tags: []string{TagRefreshToken}})
	allRules = append(allRules, Rule{Rule: *rules.GitlabPat(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.GitlabPipelineTriggerToken(), Tags: []string{TagTriggerToken}})
	allRules = append(allRules, Rule{Rule: *rules.GitlabRunnerRegistrationToken(), Tags: []string{TagRegistrationToken}})
	allRules = append(allRules, Rule{Rule: *rules.GitterAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.GoCardless(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.GrafanaApiKey(), Tags: []string{TagApiKey}})
	allRules = append(allRules, Rule{Rule: *rules.GrafanaCloudApiToken(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.GrafanaServiceAccountToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.Hashicorp(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.Heroku(), Tags: []string{TagApiKey}})
	allRules = append(allRules, Rule{Rule: *rules.HubSpot(), Tags: []string{TagApiToken, TagApiKey}})
	allRules = append(allRules, Rule{Rule: *rules.Intercom(), Tags: []string{TagApiToken, TagApiKey}})
	allRules = append(allRules, Rule{Rule: *rules.JWT(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.KrakenAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.KucoinAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.KucoinSecretKey(), Tags: []string{TagSecretKey}})
	allRules = append(allRules, Rule{Rule: *rules.LaunchDarklyAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.LinearAPIToken(), Tags: []string{TagApiToken, TagApiKey}})
	allRules = append(allRules, Rule{Rule: *rules.LinearClientSecret(), Tags: []string{TagClientSecret}})
	allRules = append(allRules, Rule{Rule: *rules.LinkedinClientID(), Tags: []string{TagClientId}})
	allRules = append(allRules, Rule{Rule: *rules.LinkedinClientSecret(), Tags: []string{TagClientSecret}})
	allRules = append(allRules, Rule{Rule: *rules.LobAPIToken(), Tags: []string{TagApiKey}})
	allRules = append(allRules, Rule{Rule: *rules.LobPubAPIToken(), Tags: []string{TagApiKey}})
	allRules = append(allRules, Rule{Rule: *rules.MailChimp(), Tags: []string{TagApiKey}})
	allRules = append(allRules, Rule{Rule: *rules.MailGunPubAPIToken(), Tags: []string{TagPublicKey}})
	allRules = append(allRules, Rule{Rule: *rules.MailGunPrivateAPIToken(), Tags: []string{TagPrivateKey}})
	allRules = append(allRules, Rule{Rule: *rules.MailGunSigningKey(), Tags: []string{TagApiKey}})
	allRules = append(allRules, Rule{Rule: *rules.MapBox(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.MattermostAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.MessageBirdAPIToken(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.MessageBirdClientID(), Tags: []string{TagClientId}})
	allRules = append(allRules, Rule{Rule: *rules.NetlifyAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.NewRelicUserID(), Tags: []string{TagApiKey}})
	allRules = append(allRules, Rule{Rule: *rules.NewRelicUserKey(), Tags: []string{TagAccessId}})
	allRules = append(allRules, Rule{Rule: *rules.NewRelicBrowserAPIKey(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.NPM(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.NytimesAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.OktaAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.PlaidAccessID(), Tags: []string{TagClientId}})
	allRules = append(allRules, Rule{Rule: *rules.PlaidSecretKey(), Tags: []string{TagSecretKey}})
	allRules = append(allRules, Rule{Rule: *rules.PlaidAccessToken(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.PlanetScalePassword(), Tags: []string{TagPassword}})
	allRules = append(allRules, Rule{Rule: *rules.PlanetScaleAPIToken(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.PlanetScaleOAuthToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.PostManAPI(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.Prefect(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.PrivateKey(), Tags: []string{TagPrivateKey}})
	allRules = append(allRules, Rule{Rule: *rules.PulumiAPIToken(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.PyPiUploadToken(), Tags: []string{TagUploadToken}})
	allRules = append(allRules, Rule{Rule: *rules.RapidAPIAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.ReadMe(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.RubyGemsAPIToken(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.SendbirdAccessID(), Tags: []string{TagAccessId}})
	allRules = append(allRules, Rule{Rule: *rules.SendbirdAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.SendGridAPIToken(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.SendInBlueAPIToken(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.SentryAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.ShippoAPIToken(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.ShopifyAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.ShopifyCustomAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.ShopifyPrivateAppAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.ShopifySharedSecret(), Tags: []string{TagPublicSecret}})
	allRules = append(allRules, Rule{Rule: *rules.SidekiqSecret(), Tags: []string{TagSecretKey}})
	allRules = append(allRules, Rule{Rule: *rules.SidekiqSensitiveUrl(), Tags: []string{TagSensitiveUrl}})
	allRules = append(allRules, Rule{Rule: *rules.SlackAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.SlackWebHook(), Tags: []string{TagWebhook}})
	allRules = append(allRules, Rule{Rule: *rules.StripeAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.SquareAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.SquareSpaceAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.SumoLogicAccessID(), Tags: []string{TagAccessId}})
	allRules = append(allRules, Rule{Rule: *rules.SumoLogicAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.TeamsWebhook(), Tags: []string{TagWebhook}})
	allRules = append(allRules, Rule{Rule: *rules.TelegramBotToken(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.TravisCIAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.Twilio(), Tags: []string{TagApiKey}})
	allRules = append(allRules, Rule{Rule: *rules.TwitchAPIToken(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.TwitterAPIKey(), Tags: []string{TagApiKey}})
	allRules = append(allRules, Rule{Rule: *rules.TwitterAPISecret(), Tags: []string{TagApiKey}})
	allRules = append(allRules, Rule{Rule: *rules.TwitterAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.TwitterAccessSecret(), Tags: []string{TagPublicSecret}})
	allRules = append(allRules, Rule{Rule: *rules.TwitterBearerToken(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.Typeform(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.VaultBatchToken(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.VaultServiceToken(), Tags: []string{TagApiToken}})
	allRules = append(allRules, Rule{Rule: *rules.YandexAPIKey(), Tags: []string{TagApiKey}})
	allRules = append(allRules, Rule{Rule: *rules.YandexAWSAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.YandexAccessToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.ZendeskSecretKey(), Tags: []string{TagSecretKey}})
	allRules = append(allRules, Rule{Rule: *secrets.AuthenticatedURL(), Tags: []string{TagPassword}})

	return allRules, nil
}

var RulesCommand = &cobra.Command{
	Use:   "rules",
	Short: "List all rules",
	Long:  `List all rules`,
	RunE: func(cmd *cobra.Command, args []string) error {

		rules, err := loadAllRules()
		if err != nil {
			return err
		}

		tab := tabwriter.NewWriter(os.Stdout, 1, 2, 2, ' ', 0)

		fmt.Fprintln(tab, "Name\tDescription\tTags")
		fmt.Fprintln(tab, "----\t----\t----")
		for _, rule := range rules {
			fmt.Fprintf(tab, "%s\t%s\t%s\n", rule.Rule.RuleID, rule.Rule.Description, strings.Join(rule.Tags, ","))
		}
		if err = tab.Flush(); err != nil {
			return err
		}

		return nil
	},
}
