package rules

import (
	"errors"
	"fmt"
	"strings"

	"regexp"
	"slices"

	"github.com/checkmarx/2ms/v4/engine/rules/ruledefine"
	"github.com/rs/zerolog/log"
)

var (
	errMissingRuleID   = fmt.Errorf("missing ruleID")
	errMissingRuleName = fmt.Errorf("missing ruleName")
	errMissingRegex    = fmt.Errorf("missing regex")
	errInvalidRegex    = fmt.Errorf("invalid regex")
	errInvalidSeverity = fmt.Errorf("invalid severity")
)

func GetDefaultRules(includeDeprecated bool) []*ruledefine.Rule { //nolint:funlen // This function contains all rule definitions
	allRules := []*ruledefine.Rule{
		ruledefine.AdafruitAPIKey(),
		ruledefine.AdobeClientID(),
		ruledefine.AdobeClientSecret(),
		ruledefine.AgeSecretKey(),
		ruledefine.Airtable(),
		ruledefine.AlgoliaApiKey(),
		ruledefine.AlibabaAccessKey(),
		ruledefine.AlibabaSecretKey(),
		ruledefine.AnthropicAdminApiKey(),
		ruledefine.AnthropicApiKey(),
		ruledefine.AsanaClientID(),
		ruledefine.AsanaClientSecret(),
		ruledefine.Atlassian(),
		ruledefine.AuthenticatedURL(),
		ruledefine.Authress(),
		ruledefine.AWS(),
		ruledefine.AzureActiveDirectoryClientSecret(),
		ruledefine.BitBucketClientID(),
		ruledefine.BitBucketClientSecret(),
		ruledefine.BittrexAccessKey(),
		ruledefine.BittrexSecretKey(),
		ruledefine.Beamer(),
		ruledefine.CodecovAccessToken(),
		ruledefine.CoinbaseAccessToken(),
		ruledefine.ClickHouseCloud(),
		ruledefine.Clojars(),
		ruledefine.CloudflareAPIKey(),
		ruledefine.CloudflareGlobalAPIKey(),
		ruledefine.CloudflareOriginCAKey(),
		ruledefine.CohereAPIToken(),
		ruledefine.ConfluentAccessToken(),
		ruledefine.ConfluentSecretKey(),
		ruledefine.Contentful(),
		ruledefine.CurlBasicAuth(),
		ruledefine.CurlHeaderAuth(),
		ruledefine.Databricks(),
		ruledefine.DatadogtokenAccessToken(),
		ruledefine.DefinedNetworkingAPIToken(),
		ruledefine.DigitalOceanPAT(),
		ruledefine.DigitalOceanOAuthToken(),
		ruledefine.DigitalOceanRefreshToken(),
		ruledefine.DiscordAPIToken(),
		ruledefine.DiscordClientID(),
		ruledefine.DiscordClientSecret(),
		ruledefine.Doppler(),
		ruledefine.DropBoxAPISecret(),
		ruledefine.DropBoxShortLivedAPIToken(),
		ruledefine.DropBoxLongLivedAPIToken(),
		ruledefine.DroneciAccessToken(),
		ruledefine.Duffel(),
		ruledefine.Dynatrace(),
		ruledefine.EasyPost(),
		ruledefine.EasyPostTestAPI(),
		ruledefine.EtsyAccessToken(),
		ruledefine.FacebookSecret(),
		ruledefine.FacebookAccessToken(),
		ruledefine.FacebookPageAccessToken(),
		ruledefine.FastlyAPIToken(),
		ruledefine.FinicityClientSecret(),
		ruledefine.FinicityAPIToken(),
		ruledefine.FlickrAccessToken(),
		ruledefine.FinnhubAccessToken(),
		ruledefine.FlutterwavePublicKey(),
		ruledefine.FlutterwaveSecretKey(),
		ruledefine.FlutterwaveEncKey(),
		ruledefine.FlyIOAccessToken(),
		ruledefine.FrameIO(),
		ruledefine.Freemius(),
		ruledefine.FreshbooksAccessToken(),
		ruledefine.GCPAPIKey(),
		ruledefine.GenericCredential(),
		ruledefine.GitHubPat(),
		ruledefine.GitHubFineGrainedPat(),
		ruledefine.GitHubOauth(),
		ruledefine.GitHubApp(),
		ruledefine.GitHubRefresh(),
		ruledefine.GitlabCiCdJobToken(),
		ruledefine.GitlabDeployToken(),
		ruledefine.GitlabFeatureFlagClientToken(),
		ruledefine.GitlabFeedToken(),
		ruledefine.GitlabIncomingMailToken(),
		ruledefine.GitlabKubernetesAgentToken(),
		ruledefine.GitlabOauthAppSecret(),
		ruledefine.GitlabPat(),
		ruledefine.GitlabPatRoutable(),
		ruledefine.GitlabPipelineTriggerToken(),
		ruledefine.GitlabRunnerRegistrationToken(),
		ruledefine.GitlabRunnerAuthenticationToken(),
		ruledefine.GitlabRunnerAuthenticationTokenRoutable(),
		ruledefine.GitlabScimToken(),
		ruledefine.GitlabSessionCookie(),
		ruledefine.GitterAccessToken(),
		ruledefine.GoCardless(),
		ruledefine.GrafanaApiKey(),
		ruledefine.GrafanaCloudApiToken(),
		ruledefine.GrafanaServiceAccountToken(),
		ruledefine.HashiCorpTerraform(),
		ruledefine.HashicorpField(),
		ruledefine.Heroku(),
		ruledefine.HerokuV2(),
		ruledefine.HubSpot(),
		ruledefine.HuggingFaceAccessToken(),
		ruledefine.HuggingFaceOrganizationApiToken(),
		ruledefine.InfracostAPIToken(),
		ruledefine.Intercom(),
		ruledefine.Intra42ClientSecret(),
		ruledefine.JFrogAPIKey(),
		ruledefine.JFrogIdentityToken(),
		ruledefine.JWT(),
		ruledefine.JWTBase64(),
		ruledefine.KrakenAccessToken(),
		ruledefine.KubernetesSecret(),
		ruledefine.KucoinAccessToken(),
		ruledefine.KucoinSecretKey(),
		ruledefine.LaunchDarklyAccessToken(),
		ruledefine.LinearAPIToken(),
		ruledefine.LinearClientSecret(),
		ruledefine.LinkedinClientID(),
		ruledefine.LinkedinClientSecret(),
		ruledefine.LobAPIToken(),
		ruledefine.LobPubAPIToken(),
		ruledefine.MailChimp(),
		ruledefine.MailGunPubAPIToken(),
		ruledefine.MailGunPrivateAPIToken(),
		ruledefine.MailGunSigningKey(),
		ruledefine.MapBox(),
		ruledefine.MattermostAccessToken(),
		ruledefine.MaxMindLicenseKey(),
		ruledefine.Meraki(),
		ruledefine.MessageBirdAPIToken(),
		ruledefine.MessageBirdClientID(),
		ruledefine.NetlifyAccessToken(),
		ruledefine.NewRelicUserID(),
		ruledefine.NewRelicUserKey(),
		ruledefine.NewRelicBrowserAPIKey(),
		ruledefine.NewRelicInsertKey(),
		ruledefine.Notion(),
		ruledefine.NPM(),
		ruledefine.NugetConfigPassword(),
		ruledefine.NytimesAccessToken(),
		ruledefine.OctopusDeployApiKey(),
		ruledefine.OktaAccessToken(),
		ruledefine.OnePasswordSecretKey(),
		ruledefine.OnePasswordServiceAccountToken(),
		ruledefine.OpenAI(),
		ruledefine.OpenshiftUserToken(),
		ruledefine.PerplexityAPIKey(),
		ruledefine.PlaidAccessID(),
		ruledefine.PlaidSecretKey(),
		ruledefine.PlaidAccessToken(),
		ruledefine.PlanetScalePassword(),
		ruledefine.PlanetScaleAPIToken(),
		ruledefine.PlanetScaleOAuthToken(),
		ruledefine.PostManAPI(),
		ruledefine.Prefect(),
		ruledefine.PrivateAIToken(),
		ruledefine.PrivateKey(),
		ruledefine.PulumiAPIToken(),
		ruledefine.PyPiUploadToken(),
		ruledefine.RapidAPIAccessToken(),
		ruledefine.ReadMe(),
		ruledefine.RubyGemsAPIToken(),
		ruledefine.ScalingoAPIToken(),
		ruledefine.SendbirdAccessID(),
		ruledefine.SendbirdAccessToken(),
		ruledefine.SendGridAPIToken(),
		ruledefine.SendInBlueAPIToken(),
		ruledefine.SentryAccessToken(),
		ruledefine.SentryOrgToken(),
		ruledefine.SentryUserToken(),
		ruledefine.SettlemintApplicationAccessToken(),
		ruledefine.SettlemintPersonalAccessToken(),
		ruledefine.SettlemintServiceAccessToken(),
		ruledefine.ShippoAPIToken(),
		ruledefine.ShopifyAccessToken(),
		ruledefine.ShopifyCustomAccessToken(),
		ruledefine.ShopifyPrivateAppAccessToken(),
		ruledefine.ShopifySharedSecret(),
		ruledefine.SidekiqSecret(),
		ruledefine.SidekiqSensitiveUrl(),
		ruledefine.SlackBotToken(),
		ruledefine.SlackAppLevelToken(),
		ruledefine.SlackLegacyToken(),
		ruledefine.SlackUserToken(),
		ruledefine.SlackConfigurationToken(),
		ruledefine.SlackConfigurationRefreshToken(),
		ruledefine.SlackLegacyBotToken(),
		ruledefine.SlackLegacyWorkspaceToken(),
		ruledefine.SlackWebHookUrl(),
		ruledefine.StripeAccessToken(),
		ruledefine.SquareAccessToken(),
		ruledefine.SquareSpaceAccessToken(),
		ruledefine.SumoLogicAccessID(),
		ruledefine.SumoLogicAccessToken(),
		ruledefine.Snyk(),
		ruledefine.TeamsWebhook(),
		ruledefine.TelegramBotToken(),
		ruledefine.TravisCIAccessToken(),
		ruledefine.Twilio(),
		ruledefine.TwitchAPIToken(),
		ruledefine.TwitterAPIKey(),
		ruledefine.TwitterAPISecret(),
		ruledefine.TwitterAccessToken(),
		ruledefine.TwitterAccessSecret(),
		ruledefine.TwitterBearerToken(),
		ruledefine.Typeform(),
		ruledefine.VaultBatchToken(),
		ruledefine.VaultServiceToken(),
		ruledefine.YandexAPIKey(),
		ruledefine.YandexAWSAccessToken(),
		ruledefine.YandexAccessToken(),
		ruledefine.ZendeskSecretKey(),
	}

	if !includeDeprecated {
		allRulesWithoutDeprecated := []*ruledefine.Rule{}
		for _, rule := range allRules {
			if !rule.Deprecated {
				allRulesWithoutDeprecated = append(allRulesWithoutDeprecated, rule)
			}
		}
		return allRulesWithoutDeprecated
	}

	return allRules
}

func getSpecialRules() []*ruledefine.Rule {
	specialRules := []*ruledefine.Rule{
		ruledefine.HardcodedPassword(),
	}

	return specialRules
}

func isRuleMatch(rule ruledefine.Rule, matchStrings []string) bool { //nolint:gocritic // hugeParam: rule is heavy but needed
	for _, matchString := range matchStrings {
		if strings.EqualFold(strings.ToLower(rule.RuleName), strings.ToLower(matchString)) {
			return true
		}
		if strings.EqualFold(rule.RuleID, matchString) {
			return true
		}
		for _, ruleTag := range rule.Tags {
			if strings.EqualFold(ruleTag, matchString) {
				return true
			}
		}
	}
	return false
}

func selectRules(allRules []*ruledefine.Rule, matchStrings []string) []*ruledefine.Rule {
	selectedRules := []*ruledefine.Rule{}

	for _, rule := range allRules {
		if isRuleMatch(*rule, matchStrings) {
			selectedRules = append(selectedRules, rule)
		}
	}
	return selectedRules
}

func ignoreRules(allRules []*ruledefine.Rule, matchStrings []string) []*ruledefine.Rule {
	selectedRules := []*ruledefine.Rule{}

	for _, rule := range allRules {
		if !isRuleMatch(*rule, matchStrings) {
			selectedRules = append(selectedRules, rule)
		}
	}
	return selectedRules
}

func FilterRules(selectedList, ignoreList, specialList []string,
	customRules []*ruledefine.Rule) []*ruledefine.Rule {
	if len(selectedList) > 0 && len(ignoreList) > 0 {
		log.Warn().
			Msgf("Both 'rule' and 'ignoreRule' flags were provided, " +
				"I will first take all in 'rule' and then remove all in 'ignoreRule' from the list.")
	}

	var selectedRules []*ruledefine.Rule

	selectedRules = GetDefaultRules(false)

	if len(selectedList) > 0 {
		selectedRules = selectRules(selectedRules, selectedList)
		customRules = selectRules(customRules, selectedList)
	}
	if len(ignoreList) > 0 {
		selectedRules = ignoreRules(selectedRules, ignoreList)
		customRules = ignoreRules(customRules, ignoreList)
	}

	selectedRules = addCustomRules(selectedRules, customRules)

	if len(specialList) > 0 {
		specialRules := getSpecialRules()
		for _, rule := range specialRules {
			for _, id := range specialList {
				if strings.EqualFold(rule.RuleName, id) {
					selectedRules = append(selectedRules, rule)
				}
			}
		}
	}

	return selectedRules
}

func addCustomRules(selectedRules, customRules []*ruledefine.Rule) []*ruledefine.Rule {
	for _, customRule := range customRules {
		// Skip deprecated custom rules
		if customRule.Deprecated {
			continue
		}
		// Check if custom rule matches any existing rule
		ruleMatch := false
		for i := range selectedRules {
			if selectedRules[i].RuleID == customRule.RuleID {
				selectedRules[i] = customRule
				ruleMatch = true
				break
			}
		}
		if !ruleMatch {
			selectedRules = append(selectedRules, customRule)
		}
	}
	return selectedRules
}

// CheckRequiredFields checks that required fields are present in the Rule.
// This is meant for user defined rules, default rules have more strict checks in unit tests
func CheckRulesRequiredFields(rulesToCheck []*ruledefine.Rule) error {
	var err error
	for i, rule := range rulesToCheck {
		if rule.RuleID == "" {
			err = errors.Join(err, buildCustomRuleError(i, rule, errMissingRuleID))
		}
		if rule.RuleName == "" {
			err = errors.Join(err, buildCustomRuleError(i, rule, errMissingRuleName))
		}

		if rule.Regex == "" {
			err = errors.Join(err, buildCustomRuleError(i, rule, errMissingRegex))
		} else {
			if _, errRegex := regexp.Compile(rule.Regex); errRegex != nil {
				invalidRegexError := fmt.Errorf("%w: %v", errInvalidRegex, errRegex)
				err = errors.Join(err, buildCustomRuleError(i, rule, invalidRegexError))
			}
		}

		if rule.Severity != "" {
			if !slices.Contains(ruledefine.SeverityOrder, rule.Severity) {
				invalidSeverityError := fmt.Errorf("%w: %s not one of (%s)", errInvalidSeverity, rule.Severity, ruledefine.SeverityOrder)
				err = errors.Join(err, buildCustomRuleError(i, rule, invalidSeverityError))
			}
		}
	}

	// Add a newline at start of error if it's not nil, for better presentation in output
	if err != nil {
		err = fmt.Errorf("\n%w", err)
	}

	return err
}

func buildCustomRuleError(ruleIndex int, rule *ruledefine.Rule, issue error) error {
	if rule.RuleID == "" {
		if rule.RuleName == "" {
			return fmt.Errorf("rule#%d: %w", ruleIndex, issue)
		}
		return fmt.Errorf("rule#%d;RuleName-%s: %w", ruleIndex, rule.RuleName, issue)
	}
	return fmt.Errorf("rule#%d;RuleID-%s: %w", ruleIndex, rule.RuleID, issue)
}
