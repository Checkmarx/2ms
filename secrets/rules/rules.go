package rules

import (
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/rules"
)

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

func getDefaultRules() *[]Rule {
	allRules := make([]Rule, 0)

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
	allRules = append(allRules, Rule{Rule: *rules.JFrogAPIKey(), Tags: []string{TagApiKey}})
	allRules = append(allRules, Rule{Rule: *rules.JFrogIdentityToken(), Tags: []string{TagAccessToken}})
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
	allRules = append(allRules, Rule{Rule: *rules.SlackBotToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.SlackAppLevelToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.SlackLegacyToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.SlackUserToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.SlackConfigurationToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.SlackConfigurationRefreshToken(), Tags: []string{TagRefreshToken}})
	allRules = append(allRules, Rule{Rule: *rules.SlackLegacyBotToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.SlackLegacyWorkspaceToken(), Tags: []string{TagAccessToken}})
	allRules = append(allRules, Rule{Rule: *rules.SlackWebHookUrl(), Tags: []string{TagWebhook}})
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
	allRules = append(allRules, Rule{Rule: *AuthenticatedURL(), Tags: []string{TagSensitiveUrl}})

	return &allRules
}

func getSpecialRules() *[]Rule {
	specialRules := []Rule{
		{Rule: *HardcodedPassword(), Tags: []string{TagPassword}},
	}

	return &specialRules
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

func selectRules(allRules *[]Rule, tags []string) *[]Rule {
	selectedRules := []Rule{}

	for _, rule := range *allRules {
		if isRuleMatch(rule, tags) {
			selectedRules = append(selectedRules, rule)
		}
	}
	return &selectedRules
}

func ignoreRules(allRules *[]Rule, tags []string) *[]Rule {
	selectedRules := []Rule{}

	for _, rule := range *allRules {
		if !isRuleMatch(rule, tags) {
			selectedRules = append(selectedRules, rule)
		}
	}
	return &selectedRules
}

func FilterRules(selectedList, ignoreList, specialList []string) *[]Rule {
	if len(selectedList) > 0 && len(ignoreList) > 0 {
		log.Warn().Msgf("Both 'rule' and 'ignoreRule' flags were provided.")
	}

	selectedRules := getDefaultRules()
	if len(selectedList) > 0 {
		selectedRules = selectRules(selectedRules, selectedList)
	}
	if len(ignoreList) > 0 {
		selectedRules = ignoreRules(selectedRules, ignoreList)
	}
	if len(specialList) > 0 {
		specialRules := getSpecialRules()
		for _, rule := range *specialRules {
			for _, id := range specialList {
				if strings.EqualFold(rule.Rule.RuleID, id) {
					*selectedRules = append(*selectedRules, rule)
				}
			}
		}
	}

	return selectedRules
}
