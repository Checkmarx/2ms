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
	allRules := &[]Rule{
		{Rule: *rules.AdafruitAPIKey(), Tags: []string{TagApiKey}},
		{Rule: *rules.AdobeClientID(), Tags: []string{TagClientId}},
		{Rule: *rules.AdobeClientSecret(), Tags: []string{TagClientSecret}},
		{Rule: *rules.AgeSecretKey(), Tags: []string{TagSecretKey}},
		{Rule: *rules.Airtable(), Tags: []string{TagApiKey}},
		{Rule: *rules.AlgoliaApiKey(), Tags: []string{TagApiKey}},
		{Rule: *rules.AlibabaAccessKey(), Tags: []string{TagAccessKey, TagAccessId}},
		{Rule: *rules.AlibabaSecretKey(), Tags: []string{TagSecretKey}},
		{Rule: *rules.AsanaClientID(), Tags: []string{TagClientId}},
		{Rule: *rules.AsanaClientSecret(), Tags: []string{TagClientSecret}},
		{Rule: *rules.Atlassian(), Tags: []string{TagApiToken}},
		{Rule: *rules.Authress(), Tags: []string{TagAccessToken}},
		{Rule: *rules.AWS(), Tags: []string{TagAccessToken}},
		{Rule: *rules.BitBucketClientID(), Tags: []string{TagClientId}},
		{Rule: *rules.BitBucketClientSecret(), Tags: []string{TagClientSecret}},
		{Rule: *rules.BittrexAccessKey(), Tags: []string{TagAccessKey}},
		{Rule: *rules.BittrexSecretKey(), Tags: []string{TagSecretKey}},
		{Rule: *rules.Beamer(), Tags: []string{TagApiToken}},
		{Rule: *rules.CodecovAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.CoinbaseAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.Clojars(), Tags: []string{TagApiToken}},
		{Rule: *rules.ConfluentAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.ConfluentSecretKey(), Tags: []string{TagSecretKey}},
		{Rule: *rules.Contentful(), Tags: []string{TagApiToken}},
		{Rule: *rules.Databricks(), Tags: []string{TagApiToken}},
		{Rule: *rules.DatadogtokenAccessToken(), Tags: []string{TagAccessToken, TagClientId}},
		{Rule: *rules.DefinedNetworkingAPIToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.DigitalOceanPAT(), Tags: []string{TagAccessToken}},
		{Rule: *rules.DigitalOceanOAuthToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.DigitalOceanRefreshToken(), Tags: []string{TagRefreshToken}},
		{Rule: *rules.DiscordAPIToken(), Tags: []string{TagApiKey, TagApiToken}},
		{Rule: *rules.DiscordClientID(), Tags: []string{TagClientId}},
		{Rule: *rules.DiscordClientSecret(), Tags: []string{TagClientSecret}},
		{Rule: *rules.Doppler(), Tags: []string{TagApiToken}},
		{Rule: *rules.DropBoxAPISecret(), Tags: []string{TagApiToken}},
		{Rule: *rules.DropBoxShortLivedAPIToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.DropBoxLongLivedAPIToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.DroneciAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.Duffel(), Tags: []string{TagApiToken}},
		{Rule: *rules.Dynatrace(), Tags: []string{TagApiToken}},
		{Rule: *rules.EasyPost(), Tags: []string{TagApiToken}},
		{Rule: *rules.EasyPostTestAPI(), Tags: []string{TagApiToken}},
		{Rule: *rules.EtsyAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.Facebook(), Tags: []string{TagApiToken}},
		{Rule: *rules.FastlyAPIToken(), Tags: []string{TagApiToken, TagApiKey}},
		{Rule: *rules.FinicityClientSecret(), Tags: []string{TagClientSecret}},
		{Rule: *rules.FinicityAPIToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.FlickrAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.FinnhubAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.FlutterwavePublicKey(), Tags: []string{TagPublicKey}},
		{Rule: *rules.FlutterwaveSecretKey(), Tags: []string{TagSecretKey}},
		{Rule: *rules.FlutterwaveEncKey(), Tags: []string{TagEncryptionKey}},
		{Rule: *rules.FrameIO(), Tags: []string{TagApiToken}},
		{Rule: *rules.FreshbooksAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.GCPAPIKey(), Tags: []string{TagApiKey}},
		{Rule: *rules.GenericCredential(), Tags: []string{TagApiKey}},
		{Rule: *rules.GitHubPat(), Tags: []string{TagAccessToken}},
		{Rule: *rules.GitHubFineGrainedPat(), Tags: []string{TagAccessToken}},
		{Rule: *rules.GitHubOauth(), Tags: []string{TagAccessToken}},
		{Rule: *rules.GitHubApp(), Tags: []string{TagAccessToken}},
		{Rule: *rules.GitHubRefresh(), Tags: []string{TagRefreshToken}},
		{Rule: *rules.GitlabPat(), Tags: []string{TagAccessToken}},
		{Rule: *rules.GitlabPipelineTriggerToken(), Tags: []string{TagTriggerToken}},
		{Rule: *rules.GitlabRunnerRegistrationToken(), Tags: []string{TagRegistrationToken}},
		{Rule: *rules.GitterAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.GoCardless(), Tags: []string{TagApiToken}},
		{Rule: *rules.GrafanaApiKey(), Tags: []string{TagApiKey}},
		{Rule: *rules.GrafanaCloudApiToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.GrafanaServiceAccountToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.Hashicorp(), Tags: []string{TagApiToken}},
		{Rule: *rules.HashicorpField(), Tags: []string{TagPassword}},
		{Rule: *rules.Heroku(), Tags: []string{TagApiKey}},
		{Rule: *rules.HubSpot(), Tags: []string{TagApiToken, TagApiKey}},
		{Rule: *rules.HuggingFaceAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.HuggingFaceOrganizationApiToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.InfracostAPIToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.Intercom(), Tags: []string{TagApiToken, TagApiKey}},
		{Rule: *rules.JFrogAPIKey(), Tags: []string{TagApiKey}},
		{Rule: *rules.JFrogIdentityToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.JWT(), Tags: []string{TagAccessToken}},
		{Rule: *rules.JWTBase64(), Tags: []string{TagAccessToken}},
		{Rule: *rules.KrakenAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.KucoinAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.KucoinSecretKey(), Tags: []string{TagSecretKey}},
		{Rule: *rules.LaunchDarklyAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.LinearAPIToken(), Tags: []string{TagApiToken, TagApiKey}},
		{Rule: *rules.LinearClientSecret(), Tags: []string{TagClientSecret}},
		{Rule: *rules.LinkedinClientID(), Tags: []string{TagClientId}},
		{Rule: *rules.LinkedinClientSecret(), Tags: []string{TagClientSecret}},
		{Rule: *rules.LobAPIToken(), Tags: []string{TagApiKey}},
		{Rule: *rules.LobPubAPIToken(), Tags: []string{TagApiKey}},
		{Rule: *rules.MailChimp(), Tags: []string{TagApiKey}},
		{Rule: *rules.MailGunPubAPIToken(), Tags: []string{TagPublicKey}},
		{Rule: *rules.MailGunPrivateAPIToken(), Tags: []string{TagPrivateKey}},
		{Rule: *rules.MailGunSigningKey(), Tags: []string{TagApiKey}},
		{Rule: *rules.MapBox(), Tags: []string{TagApiToken}},
		{Rule: *rules.MattermostAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.MessageBirdAPIToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.MessageBirdClientID(), Tags: []string{TagClientId}},
		{Rule: *rules.NetlifyAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.NewRelicUserID(), Tags: []string{TagApiKey}},
		{Rule: *rules.NewRelicUserKey(), Tags: []string{TagAccessId}},
		{Rule: *rules.NewRelicBrowserAPIKey(), Tags: []string{TagApiToken}},
		{Rule: *rules.NPM(), Tags: []string{TagAccessToken}},
		{Rule: *rules.NytimesAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.OktaAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.OpenAI(), Tags: []string{TagApiKey}},
		{Rule: *rules.PlaidAccessID(), Tags: []string{TagClientId}},
		// {Rule: *rules.PlaidSecretKey(), Tags: []string{TagSecretKey}}, https://github.com/Checkmarx/2ms/issues/226
		// {Rule: *rules.PlaidAccessToken(), Tags: []string{TagApiToken}}, https://github.com/Checkmarx/2ms/issues/226
		{Rule: *rules.PlanetScalePassword(), Tags: []string{TagPassword}},
		{Rule: *rules.PlanetScaleAPIToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.PlanetScaleOAuthToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.PostManAPI(), Tags: []string{TagApiToken}},
		{Rule: *rules.Prefect(), Tags: []string{TagApiToken}},
		{Rule: *rules.PrivateKey(), Tags: []string{TagPrivateKey}},
		{Rule: *rules.PulumiAPIToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.PyPiUploadToken(), Tags: []string{TagUploadToken}},
		{Rule: *rules.RapidAPIAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.ReadMe(), Tags: []string{TagApiToken}},
		{Rule: *rules.RubyGemsAPIToken(), Tags: []string{TagApiToken}},
		// {Rule: *rules.ScalingoAPIToken(), Tags: []string{TagApiToken}}, https://github.com/Checkmarx/2ms/issues/226
		{Rule: *rules.SendbirdAccessID(), Tags: []string{TagAccessId}},
		{Rule: *rules.SendbirdAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.SendGridAPIToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.SendInBlueAPIToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.SentryAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.ShippoAPIToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.ShopifyAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.ShopifyCustomAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.ShopifyPrivateAppAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.ShopifySharedSecret(), Tags: []string{TagPublicSecret}},
		{Rule: *rules.SidekiqSecret(), Tags: []string{TagSecretKey}},
		{Rule: *rules.SidekiqSensitiveUrl(), Tags: []string{TagSensitiveUrl}},
		{Rule: *rules.SlackBotToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.SlackAppLevelToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.SlackLegacyToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.SlackUserToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.SlackConfigurationToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.SlackConfigurationRefreshToken(), Tags: []string{TagRefreshToken}},
		{Rule: *rules.SlackLegacyBotToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.SlackLegacyWorkspaceToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.SlackWebHookUrl(), Tags: []string{TagWebhook}},
		{Rule: *rules.StripeAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.SquareAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.SquareSpaceAccessToken(), Tags: []string{TagAccessToken}},
		// {Rule: *rules.SumoLogicAccessID(), Tags: []string{TagAccessId}}, https://github.com/Checkmarx/2ms/issues/226
		{Rule: *rules.SumoLogicAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.Snyk(), Tags: []string{TagApiKey}},
		{Rule: *rules.TeamsWebhook(), Tags: []string{TagWebhook}},
		{Rule: *rules.TelegramBotToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.TravisCIAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.Twilio(), Tags: []string{TagApiKey}},
		{Rule: *rules.TwitchAPIToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.TwitterAPIKey(), Tags: []string{TagApiKey}},
		{Rule: *rules.TwitterAPISecret(), Tags: []string{TagApiKey}},
		{Rule: *rules.TwitterAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.TwitterAccessSecret(), Tags: []string{TagPublicSecret}},
		{Rule: *rules.TwitterBearerToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.Typeform(), Tags: []string{TagApiToken}},
		{Rule: *rules.VaultBatchToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.VaultServiceToken(), Tags: []string{TagApiToken}},
		{Rule: *rules.YandexAPIKey(), Tags: []string{TagApiKey}},
		{Rule: *rules.YandexAWSAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.YandexAccessToken(), Tags: []string{TagAccessToken}},
		{Rule: *rules.ZendeskSecretKey(), Tags: []string{TagSecretKey}},
		{Rule: *AuthenticatedURL(), Tags: []string{TagSensitiveUrl}},
	}

	return allRules
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
		log.Warn().Msgf("Both 'rule' and 'ignoreRule' flags were provided, I will first take all in 'rule' and then remove all in 'ignoreRule' from the list.")
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
