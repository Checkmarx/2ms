package rules

import (
	"strings"

	"github.com/rs/zerolog/log"
)

type RuleCategory string

const (
	CategoryAuthenticationAndAuthorization RuleCategory = "Authentication and Authorization"
	CategoryCryptocurrencyExchange         RuleCategory = "Cryptocurrency Exchange"
	CategoryFinancialServices              RuleCategory = "Financial Services"
	CategoryPaymentProcessing              RuleCategory = "Payment Processing"
	CategorySecurity                       RuleCategory = "Security"
	CategoryAPIAccess                      RuleCategory = "API Access"
	CategoryCICD                           RuleCategory = "CI/CD"
	CategoryCloudPlatform                  RuleCategory = "Cloud Platform"
	CategoryDatabaseAsAService             RuleCategory = "Database as a Service"
	CategoryDevelopmentPlatform            RuleCategory = "Development Platform"
	CategoryEmailDeliveryService           RuleCategory = "Email Delivery Service"
	CategoryInfrastructureAsCode           RuleCategory = "Infrastructure as Code (IaC)"
	CategoryPackageManagement              RuleCategory = "Package Management"
	CategorySourceCodeManagement           RuleCategory = "Source Code Management"
	CategoryWebHostingAndDeployment        RuleCategory = "Web Hosting and Deployment"
	CategoryBackgroundProcessingService    RuleCategory = "Background Processing Service"
	CategoryCDN                            RuleCategory = "CDN (Content Delivery Network)"
	CategoryContentManagementSystem        RuleCategory = "Content Management System (CMS)"
	CategoryCustomerSupport                RuleCategory = "Customer Support"
	CategoryDataAnalytics                  RuleCategory = "Data Analytics"
	CategoryFileStorageAndSharing          RuleCategory = "File Storage and Sharing"
	CategoryIoTPlatform                    RuleCategory = "IoT platform"
	CategoryMappingAndLocationServices     RuleCategory = "Mapping and Location Services"
	CategoryNetworking                     RuleCategory = "Networking"
	CategoryPhotoSharing                   RuleCategory = "Photo Sharing"
	CategorySaaS                           RuleCategory = "SaaS"
	CategoryShipping                       RuleCategory = "Shipping"
	CategorySoftwareDevelopment            RuleCategory = "Software Development"
	CategoryAIAndMachineLearning           RuleCategory = "AI and Machine Learning"
	CategoryApplicationMonitoring          RuleCategory = "Application Monitoring"
	CategoryECommercePlatform              RuleCategory = "E-commerce Platform"
	CategoryMarketingAutomation            RuleCategory = "Marketing Automation"
	CategoryNewsAndMedia                   RuleCategory = "News and Media"
	CategoryOnlineSurveyPlatform           RuleCategory = "Online Survey Platform"
	CategoryProjectManagement              RuleCategory = "Project Management"
	CategorySearchService                  RuleCategory = "Search Service"
	CategorySocialMedia                    RuleCategory = "Social Media"
	CategoryGeneralOrUnknown               RuleCategory = "General or Unknown"
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

func GetDefaultRules() []*Rule { //nolint:funlen // This function contains all rule definitions
	allRules := []*Rule{
		AdafruitAPIKey(),
		AdobeClientID(),
		AdobeClientSecret(),
		AgeSecretKey(),
		Airtable(),
		AlgoliaApiKey(),
		AlibabaAccessKey(),
		AlibabaSecretKey(),
		AnthropicAdminApiKey(),
		AnthropicApiKey(),
		AsanaClientID(),
		AsanaClientSecret(),
		Atlassian(),
		AuthenticatedURL(),
		Authress(),
		AWS(),
		AzureActiveDirectoryClientSecret(),
		BitBucketClientID(),
		BitBucketClientSecret(),
		BittrexAccessKey(),
		BittrexSecretKey(),
		Beamer(),
		CodecovAccessToken(),
		CoinbaseAccessToken(),
		ClickHouseCloud(),
		Clojars(),
		CloudflareAPIKey(),
		CloudflareGlobalAPIKey(),
		CloudflareOriginCAKey(),
		CohereAPIToken(),
		ConfluentAccessToken(),
		ConfluentSecretKey(),
		Contentful(),
		CurlBasicAuth(),
		CurlHeaderAuth(),
		Databricks(),
		DatadogtokenAccessToken(),
		DefinedNetworkingAPIToken(),
		DigitalOceanPAT(),
		DigitalOceanOAuthToken(),
		DigitalOceanRefreshToken(),
		DiscordAPIToken(),
		DiscordClientID(),
		DiscordClientSecret(),
		Doppler(),
		DropBoxAPISecret(),
		DropBoxShortLivedAPIToken(),
		DropBoxLongLivedAPIToken(),
		DroneciAccessToken(),
		Duffel(),
		Dynatrace(),
		EasyPost(),
		EasyPostTestAPI(),
		EtsyAccessToken(),
		FacebookSecret(),
		FacebookAccessToken(),
		FacebookPageAccessToken(),
		FastlyAPIToken(),
		FinicityClientSecret(),
		FinicityAPIToken(),
		FlickrAccessToken(),
		FinnhubAccessToken(),
		FlutterwavePublicKey(),
		FlutterwaveSecretKey(),
		FlutterwaveEncKey(),
		FlyIOAccessToken(),
		FrameIO(),
		Freemius(),
		FreshbooksAccessToken(),
		GCPAPIKey(),
		GenericCredential(),
		GitHubPat(),
		GitHubFineGrainedPat(),
		GitHubOauth(),
		GitHubApp(),
		GitHubRefresh(),
		GitlabCiCdJobToken(),
		GitlabDeployToken(),
		GitlabFeatureFlagClientToken(),
		GitlabFeedToken(),
		GitlabIncomingMailToken(),
		GitlabKubernetesAgentToken(),
		GitlabOauthAppSecret(),
		GitlabPat(),
		GitlabPatRoutable(),
		GitlabPipelineTriggerToken(),
		GitlabRunnerRegistrationToken(),
		GitlabRunnerAuthenticationToken(),
		GitlabRunnerAuthenticationTokenRoutable(),
		GitlabScimToken(),
		GitlabSessionCookie(),
		GitterAccessToken(),
		GoCardless(),
		GrafanaApiKey(),
		GrafanaCloudApiToken(),
		GrafanaServiceAccountToken(),
		HashiCorpTerraform(),
		HashicorpField(),
		Heroku(),
		HerokuV2(),
		HubSpot(),
		HuggingFaceAccessToken(),
		HuggingFaceOrganizationApiToken(),
		InfracostAPIToken(),
		Intercom(),
		Intra42ClientSecret(),
		JFrogAPIKey(),
		JFrogIdentityToken(),
		JWT(),
		JWTBase64(),
		KrakenAccessToken(),
		KubernetesSecret(),
		KucoinAccessToken(),
		KucoinSecretKey(),
		LaunchDarklyAccessToken(),
		LinearAPIToken(),
		LinearClientSecret(),
		LinkedinClientID(),
		LinkedinClientSecret(),
		LobAPIToken(),
		LobPubAPIToken(),
		MailChimp(),
		MailGunPubAPIToken(),
		MailGunPrivateAPIToken(),
		MailGunSigningKey(),
		MapBox(),
		MattermostAccessToken(),
		MaxMindLicenseKey(),
		Meraki(),
		MessageBirdAPIToken(),
		MessageBirdClientID(),
		NetlifyAccessToken(),
		NewRelicUserID(),
		NewRelicUserKey(),
		NewRelicBrowserAPIKey(),
		NewRelicInsertKey(),
		Notion(),
		NPM(),
		NugetConfigPassword(),
		NytimesAccessToken(),
		OctopusDeployApiKey(),
		OktaAccessToken(),
		OnePasswordSecretKey(),
		OnePasswordServiceAccountToken(),
		OpenAI(),
		OpenshiftUserToken(),
		PerplexityAPIKey(),
		PlaidAccessID(),
		PlaidSecretKey(),
		PlaidAccessToken(),
		PlanetScalePassword(),
		PlanetScaleAPIToken(),
		PlanetScaleOAuthToken(),
		PostManAPI(),
		Prefect(),
		PrivateAIToken(),
		PrivateKey(),
		PulumiAPIToken(),
		PyPiUploadToken(),
		RapidAPIAccessToken(),
		ReadMe(),
		RubyGemsAPIToken(),
		ScalingoAPIToken(),
		SendbirdAccessID(),
		SendbirdAccessToken(),
		SendGridAPIToken(),
		SendInBlueAPIToken(),
		SentryAccessToken(),
		SentryOrgToken(),
		SentryUserToken(),
		SettlemintApplicationAccessToken(),
		SettlemintPersonalAccessToken(),
		SettlemintServiceAccessToken(),
		ShippoAPIToken(),
		ShopifyAccessToken(),
		ShopifyCustomAccessToken(),
		ShopifyPrivateAppAccessToken(),
		ShopifySharedSecret(),
		SidekiqSecret(),
		SidekiqSensitiveUrl(),
		SlackBotToken(),
		SlackAppLevelToken(),
		SlackLegacyToken(),
		SlackUserToken(),
		SlackConfigurationToken(),
		SlackConfigurationRefreshToken(),
		SlackLegacyBotToken(),
		SlackLegacyWorkspaceToken(),
		SlackWebHookUrl(),
		StripeAccessToken(),
		SquareAccessToken(),
		SquareSpaceAccessToken(),
		SumoLogicAccessID(),
		SumoLogicAccessToken(),
		Snyk(),
		TeamsWebhook(),
		TelegramBotToken(),
		TravisCIAccessToken(),
		Twilio(),
		TwitchAPIToken(),
		TwitterAPIKey(),
		TwitterAPISecret(),
		TwitterAccessToken(),
		TwitterAccessSecret(),
		TwitterBearerToken(),
		Typeform(),
		VaultBatchToken(),
		VaultServiceToken(),
		YandexAPIKey(),
		YandexAWSAccessToken(),
		YandexAccessToken(),
		ZendeskSecretKey(),
	}

	return allRules
}

func getSpecialRules() []*Rule {
	specialRules := []*Rule{
		HardcodedPassword(),
	}

	return specialRules
}

func isRuleMatch(rule Rule, tags []string) bool { //nolint:gocritic // hugeParam: rule is heavy but needed
	for _, tag := range tags {
		if strings.EqualFold(rule.RuleID, tag) {
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

func selectRules(allRules []*Rule, tags []string) []*Rule {
	selectedRules := []*Rule{}

	for _, rule := range allRules {
		if isRuleMatch(*rule, tags) {
			selectedRules = append(selectedRules, rule)
		}
	}
	return selectedRules
}

func ignoreRules(allRules []*Rule, tags []string) []*Rule {
	selectedRules := []*Rule{}

	for _, rule := range allRules {
		if !isRuleMatch(*rule, tags) {
			selectedRules = append(selectedRules, rule)
		}
	}
	return selectedRules
}

func FilterRules(selectedList, ignoreList, specialList []string) []*Rule {
	if len(selectedList) > 0 && len(ignoreList) > 0 {
		log.Warn().
			Msgf("Both 'rule' and 'ignoreRule' flags were provided, " +
				"I will first take all in 'rule' and then remove all in 'ignoreRule' from the list.")
	}

	selectedRules := GetDefaultRules()
	if len(selectedList) > 0 {
		selectedRules = selectRules(selectedRules, selectedList)
	}
	if len(ignoreList) > 0 {
		selectedRules = ignoreRules(selectedRules, ignoreList)
	}
	if len(specialList) > 0 {
		specialRules := getSpecialRules()
		for _, rule := range specialRules {
			for _, id := range specialList {
				if strings.EqualFold(rule.RuleID, id) {
					selectedRules = append(selectedRules, rule)
				}
			}
		}
	}

	return selectedRules
}
