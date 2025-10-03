package rules

import (
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/rules"
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
	CategoryGeneralOrUnknown               RuleCategory = "general or unknown"
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
		{
			Rule:            *rules.AdafruitAPIKey(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategoryIoTPlatform, RuleType: 4},
		},
		{
			Rule:            *rules.AdobeClientID(),
			Tags:            []string{TagClientId},
			ScoreParameters: ScoreParameters{Category: CategorySaaS, RuleType: 1},
		},
		{
			Rule:            *rules.AdobeClientSecret(),
			Tags:            []string{TagClientSecret},
			ScoreParameters: ScoreParameters{Category: CategorySaaS, RuleType: 4},
		},
		{
			Rule:            *rules.AgeSecretKey(),
			Tags:            []string{TagSecretKey},
			ScoreParameters: ScoreParameters{Category: CategoryGeneralOrUnknown, RuleType: 4},
		},
		{
			Rule:            *rules.Airtable(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategoryDatabaseAsAService, RuleType: 4},
		},
		{
			Rule:            *rules.AlgoliaApiKey(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategorySearchService, RuleType: 4},
		},
		{
			Rule:            *rules.AlibabaAccessKey(),
			Tags:            []string{TagAccessKey, TagAccessId},
			ScoreParameters: ScoreParameters{Category: CategoryCloudPlatform, RuleType: 1},
		},
		{
			Rule:            *rules.AlibabaSecretKey(),
			Tags:            []string{TagSecretKey},
			ScoreParameters: ScoreParameters{Category: CategoryCloudPlatform, RuleType: 4},
		},
		{
			Rule:            *rules.AnthropicAdminApiKey(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategoryAIAndMachineLearning, RuleType: 4},
		},
		{
			Rule:            *rules.AnthropicApiKey(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategoryAIAndMachineLearning, RuleType: 4},
		},
		{
			Rule:            *rules.AsanaClientID(),
			Tags:            []string{TagClientId},
			ScoreParameters: ScoreParameters{Category: CategoryProjectManagement, RuleType: 1},
		},
		{
			Rule:            *rules.AsanaClientSecret(),
			Tags:            []string{TagClientSecret},
			ScoreParameters: ScoreParameters{Category: CategoryProjectManagement, RuleType: 4},
		},
		{
			Rule:            *OldAtlassian(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategorySoftwareDevelopment, RuleType: 4},
		},
		{
			Rule:            *OldAuthenticatedURL(),
			Tags:            []string{TagSensitiveUrl},
			ScoreParameters: ScoreParameters{Category: CategoryGeneralOrUnknown, RuleType: 4},
		},
		{
			Rule:            *rules.Authress(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryAuthenticationAndAuthorization, RuleType: 4},
		},
		{
			Rule:            *OldAWS(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryAuthenticationAndAuthorization, RuleType: 4},
		},
		{
			Rule:            *rules.AzureActiveDirectoryClientSecret(),
			Tags:            []string{TagClientSecret},
			ScoreParameters: ScoreParameters{Category: CategoryAuthenticationAndAuthorization, RuleType: 4},
		},
		{
			Rule:            *rules.BitBucketClientID(),
			Tags:            []string{TagClientId},
			ScoreParameters: ScoreParameters{Category: CategorySourceCodeManagement, RuleType: 1},
		},
		{
			Rule:            *rules.BitBucketClientSecret(),
			Tags:            []string{TagClientSecret},
			ScoreParameters: ScoreParameters{Category: CategorySourceCodeManagement, RuleType: 4},
		},
		{
			Rule:            *rules.BittrexAccessKey(),
			Tags:            []string{TagAccessKey},
			ScoreParameters: ScoreParameters{Category: CategoryCryptocurrencyExchange, RuleType: 4},
		},
		{
			Rule:            *rules.BittrexSecretKey(),
			Tags:            []string{TagSecretKey},
			ScoreParameters: ScoreParameters{Category: CategoryCryptocurrencyExchange, RuleType: 4},
		},
		{
			Rule:            *rules.Beamer(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryNewsAndMedia, RuleType: 4}},
		{
			Rule:            *rules.CodecovAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategorySecurity, RuleType: 4},
		},
		{
			Rule:            *rules.CoinbaseAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryCryptocurrencyExchange, RuleType: 4},
		},
		{
			Rule:            *rules.ClickHouseCloud(),
			Tags:            []string{TagSecretKey},
			ScoreParameters: ScoreParameters{Category: CategoryCloudPlatform, RuleType: 4},
		},
		{
			Rule:            *OldClojars(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryPackageManagement, RuleType: 4},
		},
		{
			Rule:            *rules.CloudflareAPIKey(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategoryCDN, RuleType: 4},
		},
		{
			Rule:            *rules.CloudflareGlobalAPIKey(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategoryCDN, RuleType: 4},
		},
		{
			Rule:            *rules.CloudflareOriginCAKey(),
			Tags:            []string{TagEncryptionKey},
			ScoreParameters: ScoreParameters{Category: CategoryCDN, RuleType: 4},
		},
		{
			Rule:            *rules.CohereAPIToken(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryAIAndMachineLearning, RuleType: 4},
		},
		{
			Rule:            *rules.ConfluentAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.ConfluentSecretKey(),
			Tags:            []string{TagSecretKey},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.Contentful(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryContentManagementSystem, RuleType: 4},
		},
		{
			Rule:            *rules.CurlBasicAuth(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryNetworking, RuleType: 4},
		},
		{
			Rule:            *rules.CurlHeaderAuth(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryNetworking, RuleType: 4},
		},
		{
			Rule:            *rules.Databricks(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryDataAnalytics, RuleType: 4},
		},
		{
			Rule:            *rules.DatadogtokenAccessToken(),
			Tags:            []string{TagAccessToken, TagClientId},
			ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
		},
		{
			Rule:            *rules.DefinedNetworkingAPIToken(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryNetworking, RuleType: 4},
		},
		{
			Rule:            *rules.DigitalOceanPAT(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryCloudPlatform, RuleType: 4},
		},
		{
			Rule:            *rules.DigitalOceanOAuthToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryCloudPlatform, RuleType: 4},
		},
		{
			Rule:            *rules.DigitalOceanRefreshToken(),
			Tags:            []string{TagRefreshToken},
			ScoreParameters: ScoreParameters{Category: CategoryAPIAccess, RuleType: 4},
		},
		{
			Rule:            *rules.DiscordAPIToken(),
			Tags:            []string{TagApiKey, TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.DiscordClientID(),
			Tags:            []string{TagClientId},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 1},
		},
		{
			Rule:            *rules.DiscordClientSecret(),
			Tags:            []string{TagClientSecret},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.Doppler(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
		},
		{
			Rule:            *rules.DropBoxAPISecret(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryFileStorageAndSharing, RuleType: 4},
		},
		{
			Rule:            *rules.DropBoxShortLivedAPIToken(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryFileStorageAndSharing, RuleType: 4},
		},
		{
			Rule:            *rules.DropBoxLongLivedAPIToken(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryFileStorageAndSharing, RuleType: 4},
		},
		{
			Rule:            *rules.DroneciAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
		},
		{
			Rule:            *rules.Duffel(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryAPIAccess, RuleType: 4},
		},
		{
			Rule:            *rules.Dynatrace(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
		},
		{
			Rule:            *rules.EasyPost(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryShipping, RuleType: 4},
		},
		{
			Rule:            *rules.EasyPostTestAPI(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryShipping, RuleType: 4},
		},
		{
			Rule:            *rules.EtsyAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryECommercePlatform, RuleType: 4},
		},
		{
			Rule:            *rules.FacebookSecret(),
			Tags:            []string{TagClientSecret},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.FacebookAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.FacebookPageAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.FastlyAPIToken(),
			Tags:            []string{TagApiToken, TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategoryCDN, RuleType: 4},
		},
		{
			Rule:            *rules.FinicityClientSecret(),
			Tags:            []string{TagClientSecret},
			ScoreParameters: ScoreParameters{Category: CategoryFinancialServices, RuleType: 4},
		},
		{
			Rule:            *rules.FinicityAPIToken(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryFinancialServices, RuleType: 4},
		},
		{
			Rule:            *rules.FlickrAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryPhotoSharing, RuleType: 4},
		},
		{
			Rule:            *rules.FinnhubAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryFinancialServices, RuleType: 4},
		},
		{
			Rule:            *rules.FlutterwavePublicKey(),
			Tags:            []string{TagPublicKey},
			ScoreParameters: ScoreParameters{Category: CategoryPaymentProcessing, RuleType: 4},
		},
		{
			Rule:            *rules.FlutterwaveSecretKey(),
			Tags:            []string{TagSecretKey},
			ScoreParameters: ScoreParameters{Category: CategoryPaymentProcessing, RuleType: 4},
		},
		{
			Rule:            *rules.FlutterwaveEncKey(),
			Tags:            []string{TagEncryptionKey},
			ScoreParameters: ScoreParameters{Category: CategoryPaymentProcessing, RuleType: 4},
		},
		{
			Rule:            *rules.FlyIOAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryWebHostingAndDeployment, RuleType: 4},
		},
		{
			Rule:            *rules.FrameIO(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryNewsAndMedia, RuleType: 4},
		},
		{
			Rule:            *rules.Freemius(),
			Tags:            []string{TagSecretKey},
			ScoreParameters: ScoreParameters{Category: CategoryECommercePlatform, RuleType: 4},
		},
		{
			Rule:            *rules.FreshbooksAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryFinancialServices, RuleType: 4},
		},
		{
			Rule:            *rules.GCPAPIKey(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategoryCloudPlatform, RuleType: 4},
		},
		{
			Rule:            *OldGenericCredential(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategoryGeneralOrUnknown, RuleType: 4},
		},
		{
			Rule:            *rules.GitHubPat(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryDevelopmentPlatform, RuleType: 4},
		},
		{
			Rule:            *rules.GitHubFineGrainedPat(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryAPIAccess, RuleType: 4},
		},
		{
			Rule:            *rules.GitHubOauth(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryAuthenticationAndAuthorization, RuleType: 4},
		},
		{
			Rule:            *OldGitHubApp(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
		},
		{
			Rule:            *rules.GitHubRefresh(),
			Tags:            []string{TagRefreshToken},
			ScoreParameters: ScoreParameters{Category: CategoryAuthenticationAndAuthorization, RuleType: 4},
		},
		{
			Rule:            *rules.GitlabCiCdJobToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
		},
		{
			Rule:            *rules.GitlabDeployToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
		},
		{
			Rule:            *rules.GitlabFeatureFlagClientToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
		},
		{
			Rule:            *rules.GitlabFeedToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
		},
		{
			Rule:            *rules.GitlabIncomingMailToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategorySourceCodeManagement, RuleType: 4},
		},
		{
			Rule:            *rules.GitlabKubernetesAgentToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategorySourceCodeManagement, RuleType: 4},
		},
		{
			Rule:            *rules.GitlabOauthAppSecret(),
			Tags:            []string{TagSecretKey},
			ScoreParameters: ScoreParameters{Category: CategorySourceCodeManagement, RuleType: 4},
		},
		{
			Rule:            *rules.GitlabPat(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategorySourceCodeManagement, RuleType: 4},
		},
		{
			Rule:            *OldGitlabPatRoutable(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategorySourceCodeManagement, RuleType: 4},
		},
		{
			Rule:            *rules.GitlabPipelineTriggerToken(),
			Tags:            []string{TagTriggerToken},
			ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
		},
		{
			Rule:            *rules.GitlabRunnerRegistrationToken(),
			Tags:            []string{TagRegistrationToken},
			ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
		},
		{
			Rule:            *rules.GitlabRunnerAuthenticationToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
		},
		{
			Rule:            *OldGitlabRunnerAuthenticationTokenRoutable(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
		},
		{
			Rule:            *rules.GitlabScimToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
		},
		{
			Rule:            *rules.GitlabSessionCookie(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategorySourceCodeManagement, RuleType: 4},
		},
		{
			Rule:            *rules.GitterAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.GoCardless(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryPaymentProcessing, RuleType: 4},
		},
		{
			Rule:            *rules.GrafanaApiKey(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
		},
		{
			Rule:            *rules.GrafanaCloudApiToken(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
		},
		{
			Rule:            *rules.GrafanaServiceAccountToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
		},
		{
			Rule:            *rules.HashiCorpTerraform(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryInfrastructureAsCode, RuleType: 4},
		},
		{
			Rule:            *rules.HashicorpField(),
			Tags:            []string{TagPassword},
			ScoreParameters: ScoreParameters{Category: CategoryInfrastructureAsCode, RuleType: 4},
		},
		{
			Rule:            *rules.Heroku(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategorySaaS, RuleType: 4},
		},
		{
			Rule:            *rules.HerokuV2(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategorySaaS, RuleType: 4},
		},
		{
			Rule:            *rules.HubSpot(),
			Tags:            []string{TagApiToken, TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategoryMarketingAutomation, RuleType: 4},
		},
		{
			Rule:            *rules.HuggingFaceAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryAIAndMachineLearning, RuleType: 4},
		},
		{
			Rule:            *rules.HuggingFaceOrganizationApiToken(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryAIAndMachineLearning, RuleType: 4},
		},
		{
			Rule:            *rules.InfracostAPIToken(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryFinancialServices, RuleType: 4},
		},
		{
			Rule:            *rules.Intercom(),
			Tags:            []string{TagApiToken, TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategoryCustomerSupport, RuleType: 4},
		},
		{
			Rule:            *rules.Intra42ClientSecret(),
			Tags:            []string{TagClientSecret},
			ScoreParameters: ScoreParameters{Category: CategoryGeneralOrUnknown, RuleType: 4},
		},
		{
			Rule:            *rules.JFrogAPIKey(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
		},
		{
			Rule:            *rules.JFrogIdentityToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
		},
		{
			Rule:            *rules.JWT(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryGeneralOrUnknown, RuleType: 4},
		},
		{
			Rule:            *rules.JWTBase64(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryGeneralOrUnknown, RuleType: 4},
		},
		{
			Rule:            *rules.KrakenAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryCryptocurrencyExchange, RuleType: 4},
		},
		{
			Rule:            *rules.KubernetesSecret(),
			Tags:            []string{TagSecretKey},
			ScoreParameters: ScoreParameters{Category: CategoryCloudPlatform, RuleType: 4},
		},
		{
			Rule:            *rules.KucoinAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryCryptocurrencyExchange, RuleType: 4},
		},
		{
			Rule:            *rules.KucoinSecretKey(),
			Tags:            []string{TagSecretKey},
			ScoreParameters: ScoreParameters{Category: CategoryCryptocurrencyExchange, RuleType: 4},
		},
		{
			Rule:            *rules.LaunchDarklyAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategorySoftwareDevelopment, RuleType: 4},
		},
		{
			Rule:            *rules.LinearAPIToken(),
			Tags:            []string{TagApiToken, TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategoryAPIAccess, RuleType: 4},
		},
		{
			Rule:            *rules.LinearClientSecret(),
			Tags:            []string{TagClientSecret},
			ScoreParameters: ScoreParameters{Category: CategoryAuthenticationAndAuthorization, RuleType: 4},
		},
		{
			Rule:            *rules.LinkedinClientID(),
			Tags:            []string{TagClientId},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 1},
		},
		{
			Rule:            *rules.LinkedinClientSecret(),
			Tags:            []string{TagClientSecret},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.LobAPIToken(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategoryAPIAccess, RuleType: 4},
		},
		{
			Rule:            *rules.LobPubAPIToken(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategoryAPIAccess, RuleType: 4},
		},
		{
			Rule:            *rules.MailChimp(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategoryEmailDeliveryService, RuleType: 4},
		},
		{
			Rule:            *rules.MailGunPubAPIToken(),
			Tags:            []string{TagPublicKey},
			ScoreParameters: ScoreParameters{Category: CategoryEmailDeliveryService, RuleType: 4},
		},
		{
			Rule:            *rules.MailGunPrivateAPIToken(),
			Tags:            []string{TagPrivateKey},
			ScoreParameters: ScoreParameters{Category: CategoryEmailDeliveryService, RuleType: 4},
		},
		{
			Rule:            *rules.MailGunSigningKey(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategoryEmailDeliveryService, RuleType: 4},
		},
		{
			Rule:            *rules.MapBox(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryMappingAndLocationServices, RuleType: 4},
		},
		{
			Rule:            *rules.MattermostAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.MaxMindLicenseKey(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategoryDataAnalytics, RuleType: 4},
		},
		{
			Rule:            *rules.Meraki(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategoryNetworking, RuleType: 4},
		},
		{
			Rule:            *rules.MessageBirdAPIToken(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.MessageBirdClientID(),
			Tags:            []string{TagClientId},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 1},
		},
		{
			Rule:            *rules.NetlifyAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryWebHostingAndDeployment, RuleType: 4},
		},
		{
			Rule:            *rules.NewRelicUserID(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 1},
		},
		{
			Rule:            *rules.NewRelicUserKey(),
			Tags:            []string{TagAccessId},
			ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
		},
		{
			Rule:            *rules.NewRelicBrowserAPIKey(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
		},
		{
			Rule:            *rules.NewRelicInsertKey(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
		},
		{
			Rule:            *rules.Notion(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategorySaaS, RuleType: 4},
		},
		{
			Rule:            *rules.NPM(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryPackageManagement, RuleType: 4},
		},
		{
			Rule:            *rules.NugetConfigPassword(),
			Tags:            []string{TagPassword},
			ScoreParameters: ScoreParameters{Category: CategoryPackageManagement, RuleType: 4},
		},
		{
			Rule:            *rules.NytimesAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryNewsAndMedia, RuleType: 4},
		},
		{
			Rule:            *rules.OctopusDeployApiKey(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
		},
		{
			Rule:            *rules.OktaAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryAuthenticationAndAuthorization, RuleType: 4},
		},
		{
			Rule:            *OldOnePasswordSecretKey(),
			Tags:            []string{TagPrivateKey},
			ScoreParameters: ScoreParameters{Category: CategoryAuthenticationAndAuthorization, RuleType: 4},
		},
		{
			Rule:            *rules.OnePasswordServiceAccountToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryAuthenticationAndAuthorization, RuleType: 4},
		},
		{
			Rule:            *rules.OpenAI(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategoryAIAndMachineLearning, RuleType: 4},
		},
		{
			Rule:            *rules.OpenshiftUserToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryCloudPlatform, RuleType: 4},
		},
		{
			Rule:            *rules.PerplexityAPIKey(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategoryAIAndMachineLearning, RuleType: 4},
		},
		{
			Rule:            *OldPlaidAccessID(),
			Tags:            []string{TagClientId},
			ScoreParameters: ScoreParameters{Category: CategoryFinancialServices, RuleType: 1},
		},
		{
			Rule:            *rules.PlaidSecretKey(),
			Tags:            []string{TagSecretKey},
			ScoreParameters: ScoreParameters{Category: CategoryFinancialServices, RuleType: 4},
		},
		{
			Rule:            *rules.PlaidAccessToken(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryFinancialServices, RuleType: 4},
		},
		{
			Rule:            *rules.PlanetScalePassword(),
			Tags:            []string{TagPassword},
			ScoreParameters: ScoreParameters{Category: CategoryDatabaseAsAService, RuleType: 4},
		},
		{
			Rule:            *rules.PlanetScaleAPIToken(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryDatabaseAsAService, RuleType: 4},
		},
		{
			Rule:            *rules.PlanetScaleOAuthToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryDatabaseAsAService, RuleType: 4},
		},
		{
			Rule:            *rules.PostManAPI(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryAPIAccess, RuleType: 4},
		},
		{
			Rule:            *rules.Prefect(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryAPIAccess, RuleType: 4},
		},
		{
			Rule:            *rules.PrivateAIToken(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryAIAndMachineLearning, RuleType: 4},
		},
		{
			Rule:            *OldPrivateKey(),
			Tags:            []string{TagPrivateKey},
			ScoreParameters: ScoreParameters{Category: CategoryGeneralOrUnknown, RuleType: 4},
		},
		{
			Rule:            *rules.PulumiAPIToken(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryCloudPlatform, RuleType: 4},
		},
		{
			Rule:            *rules.PyPiUploadToken(),
			Tags:            []string{TagUploadToken},
			ScoreParameters: ScoreParameters{Category: CategoryPackageManagement, RuleType: 4},
		},
		{
			Rule:            *rules.RapidAPIAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryAPIAccess, RuleType: 4},
		},
		{
			Rule:            *rules.ReadMe(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryAPIAccess, RuleType: 4},
		},
		{
			Rule:            *rules.RubyGemsAPIToken(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryPackageManagement, RuleType: 4},
		},
		{
			Rule:            *rules.ScalingoAPIToken(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryWebHostingAndDeployment, RuleType: 4},
		},
		{
			Rule:            *rules.SendbirdAccessID(),
			Tags:            []string{TagAccessId},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 1},
		},
		{
			Rule:            *rules.SendbirdAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.SendGridAPIToken(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryEmailDeliveryService, RuleType: 4},
		},
		{
			Rule:            *rules.SendInBlueAPIToken(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryEmailDeliveryService, RuleType: 4},
		},
		{
			Rule:            *rules.SentryAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
		},
		{
			Rule:            *rules.SentryOrgToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
		},
		{
			Rule:            *rules.SentryUserToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
		},
		{
			Rule:            *rules.SettlemintApplicationAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategorySoftwareDevelopment, RuleType: 4},
		},
		{
			Rule:            *rules.SettlemintPersonalAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategorySoftwareDevelopment, RuleType: 4},
		},
		{
			Rule:            *rules.SettlemintServiceAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategorySoftwareDevelopment, RuleType: 4},
		},
		{
			Rule:            *rules.ShippoAPIToken(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryShipping, RuleType: 4},
		},
		{
			Rule:            *rules.ShopifyAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryECommercePlatform, RuleType: 4},
		},
		{
			Rule:            *rules.ShopifyCustomAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryECommercePlatform, RuleType: 4},
		},
		{
			Rule:            *rules.ShopifyPrivateAppAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryECommercePlatform, RuleType: 4},
		},
		{
			Rule:            *rules.ShopifySharedSecret(),
			Tags:            []string{TagPublicSecret},
			ScoreParameters: ScoreParameters{Category: CategoryECommercePlatform, RuleType: 4},
		},
		{
			Rule:            *rules.SidekiqSecret(),
			Tags:            []string{TagSecretKey},
			ScoreParameters: ScoreParameters{Category: CategoryBackgroundProcessingService, RuleType: 4},
		},
		{
			Rule:            *rules.SidekiqSensitiveUrl(),
			Tags:            []string{TagSensitiveUrl},
			ScoreParameters: ScoreParameters{Category: CategoryBackgroundProcessingService, RuleType: 4},
		},
		{
			Rule:            *rules.SlackBotToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.SlackAppLevelToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.SlackLegacyToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.SlackUserToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.SlackConfigurationToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.SlackConfigurationRefreshToken(),
			Tags:            []string{TagRefreshToken},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.SlackLegacyBotToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.SlackLegacyWorkspaceToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.SlackWebHookUrl(),
			Tags:            []string{TagWebhook},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.StripeAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryPaymentProcessing, RuleType: 4},
		},
		{
			Rule:            *rules.SquareAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryPaymentProcessing, RuleType: 4},
		},
		{
			Rule:            *rules.SquareSpaceAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryWebHostingAndDeployment, RuleType: 4},
		},
		{
			Rule:            *OldSumoLogicAccessID(),
			Tags:            []string{TagAccessId},
			ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
		},
		{
			Rule:            *OldSumoLogicAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
		},
		{
			Rule:            *rules.Snyk(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategorySecurity, RuleType: 4},
		},
		{
			Rule:            *rules.TeamsWebhook(),
			Tags:            []string{TagWebhook},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.TelegramBotToken(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.TravisCIAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
		},
		{
			Rule:            *rules.Twilio(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.TwitchAPIToken(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryNewsAndMedia, RuleType: 4},
		},
		{
			Rule:            *rules.TwitterAPIKey(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.TwitterAPISecret(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.TwitterAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.TwitterAccessSecret(),
			Tags:            []string{TagPublicSecret},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.TwitterBearerToken(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
		},
		{
			Rule:            *rules.Typeform(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryOnlineSurveyPlatform, RuleType: 4},
		},
		{
			Rule:            *rules.VaultBatchToken(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategorySecurity, RuleType: 4},
		},
		{
			Rule:            *OldVaultServiceToken(),
			Tags:            []string{TagApiToken},
			ScoreParameters: ScoreParameters{Category: CategoryAuthenticationAndAuthorization, RuleType: 4},
		},
		{
			Rule:            *rules.YandexAPIKey(),
			Tags:            []string{TagApiKey},
			ScoreParameters: ScoreParameters{Category: CategoryCloudPlatform, RuleType: 4},
		},
		{
			Rule:            *rules.YandexAWSAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryCloudPlatform, RuleType: 4},
		},
		{
			Rule:            *rules.YandexAccessToken(),
			Tags:            []string{TagAccessToken},
			ScoreParameters: ScoreParameters{Category: CategoryCloudPlatform, RuleType: 4},
		},
		{
			Rule:            *rules.ZendeskSecretKey(),
			Tags:            []string{TagSecretKey},
			ScoreParameters: ScoreParameters{Category: CategoryCustomerSupport, RuleType: 4},
		},
	}

	return allRules
}
func GetDefaultRulesV2() []*NewRule { //nolint:funlen // This function contains all rule definitions
	allRules := []*NewRule{
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
		{
			Rule:            *HardcodedPassword(),
			Tags:            []string{TagPassword},
			ScoreParameters: ScoreParameters{Category: CategoryGeneralOrUnknown, RuleType: 4},
		},
	}

	return specialRules
}

func isRuleMatch(rule Rule, tags []string) bool { //nolint:gocritic // hugeParam: rule is heavy but needed
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
				if strings.EqualFold(rule.Rule.RuleID, id) {
					selectedRules = append(selectedRules, rule)
				}
			}
		}
	}

	return selectedRules
}
