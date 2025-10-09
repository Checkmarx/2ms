package score

import (
	"testing"

	"github.com/checkmarx/2ms/v4/engine/rules"
	"github.com/checkmarx/2ms/v4/lib/secrets"
	"github.com/stretchr/testify/assert"
)

func TestScore(t *testing.T) {
	specialRule := rules.HardcodedPassword()
	allRules := rules.FilterRules([]string{}, []string{}, []string{specialRule.RuleID})

	expectedCvssScores := map[string][3]float64{ // ruleID -> Valid, Invalid, Unknown
		rules.AdafruitAPIKey().RuleID:                          {9.4, 3.4, 6.4},
		rules.AdobeClientID().RuleID:                           {5.8, 1, 2.8},
		rules.AdobeClientSecret().RuleID:                       {9.4, 3.4, 6.4},
		rules.AgeSecretKey().RuleID:                            {10, 5.2, 8.2},
		rules.Airtable().RuleID:                                {10, 5.2, 8.2},
		rules.AlgoliaApiKey().RuleID:                           {7.6, 1.6, 4.6},
		rules.AlibabaAccessKey().RuleID:                        {7.6, 1.6, 4.6},
		rules.AlibabaSecretKey().RuleID:                        {10, 5.2, 8.2},
		rules.AnthropicAdminApiKey().RuleID:                    {7.6, 1.6, 4.6},
		rules.AnthropicApiKey().RuleID:                         {7.6, 1.6, 4.6},
		rules.AsanaClientID().RuleID:                           {4, 1, 1},
		rules.AsanaClientSecret().RuleID:                       {7.6, 1.6, 4.6},
		rules.Atlassian().RuleID:                               {9.4, 3.4, 6.4},
		rules.AuthenticatedURL().RuleID:                        {10, 5.2, 8.2},
		rules.Authress().RuleID:                                {10, 7, 10},
		rules.AWS().RuleID:                                     {10, 7, 10},
		rules.AzureActiveDirectoryClientSecret().RuleID:        {10, 7, 10},
		rules.BitBucketClientID().RuleID:                       {7.6, 1.6, 4.6},
		rules.BitBucketClientSecret().RuleID:                   {10, 5.2, 8.2},
		rules.BittrexAccessKey().RuleID:                        {10, 7, 10},
		rules.BittrexSecretKey().RuleID:                        {10, 7, 10},
		rules.Beamer().RuleID:                                  {7.6, 1.6, 4.6},
		rules.CodecovAccessToken().RuleID:                      {10, 7, 10},
		rules.CoinbaseAccessToken().RuleID:                     {10, 7, 10},
		rules.ClickHouseCloud().RuleID:                         {10, 5.2, 8.2},
		rules.Clojars().RuleID:                                 {10, 5.2, 8.2},
		rules.CloudflareAPIKey().RuleID:                        {9.4, 3.4, 6.4},
		rules.CloudflareGlobalAPIKey().RuleID:                  {9.4, 3.4, 6.4},
		rules.CloudflareOriginCAKey().RuleID:                   {9.4, 3.4, 6.4},
		rules.CohereAPIToken().RuleID:                          {7.6, 1.6, 4.6},
		rules.ConfluentAccessToken().RuleID:                    {7.6, 1.6, 4.6},
		rules.ConfluentSecretKey().RuleID:                      {7.6, 1.6, 4.6},
		rules.Contentful().RuleID:                              {9.4, 3.4, 6.4},
		rules.CurlBasicAuth().RuleID:                           {9.4, 3.4, 6.4},
		rules.CurlHeaderAuth().RuleID:                          {9.4, 3.4, 6.4},
		rules.Databricks().RuleID:                              {9.4, 3.4, 6.4},
		rules.DatadogtokenAccessToken().RuleID:                 {7.6, 1.6, 4.6},
		rules.DefinedNetworkingAPIToken().RuleID:               {9.4, 3.4, 6.4},
		rules.DigitalOceanPAT().RuleID:                         {10, 5.2, 8.2},
		rules.DigitalOceanOAuthToken().RuleID:                  {10, 5.2, 8.2},
		rules.DigitalOceanRefreshToken().RuleID:                {10, 5.2, 8.2},
		rules.DiscordAPIToken().RuleID:                         {7.6, 1.6, 4.6},
		rules.DiscordClientID().RuleID:                         {4, 1, 1},
		rules.DiscordClientSecret().RuleID:                     {7.6, 1.6, 4.6},
		rules.Doppler().RuleID:                                 {10, 5.2, 8.2},
		rules.DropBoxAPISecret().RuleID:                        {9.4, 3.4, 6.4},
		rules.DropBoxShortLivedAPIToken().RuleID:               {9.4, 3.4, 6.4},
		rules.DropBoxLongLivedAPIToken().RuleID:                {9.4, 3.4, 6.4},
		rules.DroneciAccessToken().RuleID:                      {10, 5.2, 8.2},
		rules.Duffel().RuleID:                                  {10, 5.2, 8.2},
		rules.Dynatrace().RuleID:                               {7.6, 1.6, 4.6},
		rules.EasyPost().RuleID:                                {9.4, 3.4, 6.4},
		rules.EasyPostTestAPI().RuleID:                         {9.4, 3.4, 6.4},
		rules.EtsyAccessToken().RuleID:                         {7.6, 1.6, 4.6},
		rules.FacebookAccessToken().RuleID:                     {7.6, 1.6, 4.6},
		rules.FacebookPageAccessToken().RuleID:                 {7.6, 1.6, 4.6},
		rules.FacebookSecret().RuleID:                          {7.6, 1.6, 4.6},
		rules.FastlyAPIToken().RuleID:                          {9.4, 3.4, 6.4},
		rules.FinicityClientSecret().RuleID:                    {10, 7, 10},
		rules.FinicityAPIToken().RuleID:                        {10, 7, 10},
		rules.FlickrAccessToken().RuleID:                       {9.4, 3.4, 6.4},
		rules.FinnhubAccessToken().RuleID:                      {10, 7, 10},
		rules.FlutterwavePublicKey().RuleID:                    {10, 7, 10},
		rules.FlutterwaveSecretKey().RuleID:                    {10, 7, 10},
		rules.FlutterwaveEncKey().RuleID:                       {10, 7, 10},
		rules.FlyIOAccessToken().RuleID:                        {10, 5.2, 8.2},
		rules.FrameIO().RuleID:                                 {7.6, 1.6, 4.6},
		rules.Freemius().RuleID:                                {7.6, 1.6, 4.6},
		rules.FreshbooksAccessToken().RuleID:                   {10, 7, 10},
		rules.GCPAPIKey().RuleID:                               {10, 5.2, 8.2},
		rules.GenericCredential().RuleID:                       {10, 5.2, 8.2},
		rules.GitHubPat().RuleID:                               {10, 5.2, 8.2},
		rules.GitHubFineGrainedPat().RuleID:                    {10, 5.2, 8.2},
		rules.GitHubOauth().RuleID:                             {10, 7, 10},
		rules.GitHubApp().RuleID:                               {10, 5.2, 8.2},
		rules.GitHubRefresh().RuleID:                           {10, 7, 10},
		rules.GitlabCiCdJobToken().RuleID:                      {10, 5.2, 8.2},
		rules.GitlabDeployToken().RuleID:                       {10, 5.2, 8.2},
		rules.GitlabFeatureFlagClientToken().RuleID:            {10, 5.2, 8.2},
		rules.GitlabFeedToken().RuleID:                         {10, 5.2, 8.2},
		rules.GitlabIncomingMailToken().RuleID:                 {10, 5.2, 8.2},
		rules.GitlabKubernetesAgentToken().RuleID:              {10, 5.2, 8.2},
		rules.GitlabOauthAppSecret().RuleID:                    {10, 5.2, 8.2},
		rules.GitlabPat().RuleID:                               {10, 5.2, 8.2},
		rules.GitlabPatRoutable().RuleID:                       {10, 5.2, 8.2},
		rules.GitlabPipelineTriggerToken().RuleID:              {10, 5.2, 8.2},
		rules.GitlabRunnerRegistrationToken().RuleID:           {10, 5.2, 8.2},
		rules.GitlabRunnerAuthenticationToken().RuleID:         {10, 5.2, 8.2},
		rules.GitlabRunnerAuthenticationTokenRoutable().RuleID: {10, 5.2, 8.2},
		rules.GitlabScimToken().RuleID:                         {10, 5.2, 8.2},
		rules.GitlabSessionCookie().RuleID:                     {10, 5.2, 8.2},
		rules.GitterAccessToken().RuleID:                       {7.6, 1.6, 4.6},
		rules.GoCardless().RuleID:                              {10, 7, 10},
		rules.GrafanaApiKey().RuleID:                           {7.6, 1.6, 4.6},
		rules.GrafanaCloudApiToken().RuleID:                    {7.6, 1.6, 4.6},
		rules.GrafanaServiceAccountToken().RuleID:              {7.6, 1.6, 4.6},
		rules.HashiCorpTerraform().RuleID:                      {10, 5.2, 8.2},
		rules.HashicorpField().RuleID:                          {10, 5.2, 8.2},
		rules.Heroku().RuleID:                                  {9.4, 3.4, 6.4},
		rules.HerokuV2().RuleID:                                {9.4, 3.4, 6.4},
		rules.HubSpot().RuleID:                                 {7.6, 1.6, 4.6},
		rules.HuggingFaceAccessToken().RuleID:                  {7.6, 1.6, 4.6},
		rules.HuggingFaceOrganizationApiToken().RuleID:         {7.6, 1.6, 4.6},
		rules.InfracostAPIToken().RuleID:                       {10, 7, 10},
		rules.Intercom().RuleID:                                {9.4, 3.4, 6.4},
		rules.Intra42ClientSecret().RuleID:                     {10, 5.2, 8.2},
		rules.JFrogAPIKey().RuleID:                             {10, 5.2, 8.2},
		rules.JFrogIdentityToken().RuleID:                      {10, 5.2, 8.2},
		rules.JWT().RuleID:                                     {10, 5.2, 8.2},
		rules.JWTBase64().RuleID:                               {10, 5.2, 8.2},
		rules.KrakenAccessToken().RuleID:                       {10, 7, 10},
		rules.KubernetesSecret().RuleID:                        {10, 5.2, 8.2},
		rules.KucoinAccessToken().RuleID:                       {10, 7, 10},
		rules.KucoinSecretKey().RuleID:                         {10, 7, 10},
		rules.LaunchDarklyAccessToken().RuleID:                 {9.4, 3.4, 6.4},
		rules.LinearAPIToken().RuleID:                          {10, 5.2, 8.2},
		rules.LinearClientSecret().RuleID:                      {10, 7, 10},
		rules.LinkedinClientID().RuleID:                        {4, 1, 1},
		rules.LinkedinClientSecret().RuleID:                    {7.6, 1.6, 4.6},
		rules.LobAPIToken().RuleID:                             {10, 5.2, 8.2},
		rules.LobPubAPIToken().RuleID:                          {10, 5.2, 8.2},
		rules.MailChimp().RuleID:                               {10, 5.2, 8.2},
		rules.MailGunPubAPIToken().RuleID:                      {10, 5.2, 8.2},
		rules.MailGunPrivateAPIToken().RuleID:                  {10, 5.2, 8.2},
		rules.MailGunSigningKey().RuleID:                       {10, 5.2, 8.2},
		rules.MapBox().RuleID:                                  {9.4, 3.4, 6.4},
		rules.MattermostAccessToken().RuleID:                   {7.6, 1.6, 4.6},
		rules.MaxMindLicenseKey().RuleID:                       {9.4, 3.4, 6.4},
		rules.Meraki().RuleID:                                  {9.4, 3.4, 6.4},
		rules.MessageBirdAPIToken().RuleID:                     {7.6, 1.6, 4.6},
		rules.MessageBirdClientID().RuleID:                     {4, 1, 1},
		rules.NetlifyAccessToken().RuleID:                      {10, 5.2, 8.2},
		rules.NewRelicUserID().RuleID:                          {4, 1, 1},
		rules.NewRelicUserKey().RuleID:                         {7.6, 1.6, 4.6},
		rules.NewRelicBrowserAPIKey().RuleID:                   {7.6, 1.6, 4.6},
		rules.NewRelicInsertKey().RuleID:                       {7.6, 1.6, 4.6},
		rules.Notion().RuleID:                                  {9.4, 3.4, 6.4},
		rules.NPM().RuleID:                                     {10, 5.2, 8.2},
		rules.NugetConfigPassword().RuleID:                     {10, 5.2, 8.2},
		rules.OctopusDeployApiKey().RuleID:                     {10, 5.2, 8.2},
		rules.NytimesAccessToken().RuleID:                      {7.6, 1.6, 4.6},
		rules.OktaAccessToken().RuleID:                         {10, 7, 10},
		rules.OnePasswordSecretKey().RuleID:                    {10, 7, 10},
		rules.OnePasswordServiceAccountToken().RuleID:          {10, 7, 10},
		rules.OpenAI().RuleID:                                  {7.6, 1.6, 4.6},
		rules.OpenshiftUserToken().RuleID:                      {10, 5.2, 8.2},
		rules.PerplexityAPIKey().RuleID:                        {7.6, 1.6, 4.6},
		rules.PlaidAccessID().RuleID:                           {9.4, 3.4, 6.4},
		rules.PlaidSecretKey().RuleID:                          {10, 7, 10},
		rules.PlaidAccessToken().RuleID:                        {10, 7, 10},
		rules.PlanetScalePassword().RuleID:                     {10, 5.2, 8.2},
		rules.PlanetScaleAPIToken().RuleID:                     {10, 5.2, 8.2},
		rules.PlanetScaleOAuthToken().RuleID:                   {10, 5.2, 8.2},
		rules.PostManAPI().RuleID:                              {10, 5.2, 8.2},
		rules.Prefect().RuleID:                                 {10, 5.2, 8.2},
		rules.PrivateAIToken().RuleID:                          {7.6, 1.6, 4.6},
		rules.PrivateKey().RuleID:                              {10, 5.2, 8.2},
		rules.PulumiAPIToken().RuleID:                          {10, 5.2, 8.2},
		rules.PyPiUploadToken().RuleID:                         {10, 5.2, 8.2},
		rules.RapidAPIAccessToken().RuleID:                     {10, 5.2, 8.2},
		rules.ReadMe().RuleID:                                  {10, 5.2, 8.2},
		rules.RubyGemsAPIToken().RuleID:                        {10, 5.2, 8.2},
		rules.ScalingoAPIToken().RuleID:                        {10, 5.2, 8.2},
		rules.SendbirdAccessID().RuleID:                        {4, 1, 1},
		rules.SendbirdAccessToken().RuleID:                     {7.6, 1.6, 4.6},
		rules.SendGridAPIToken().RuleID:                        {10, 5.2, 8.2},
		rules.SendInBlueAPIToken().RuleID:                      {10, 5.2, 8.2},
		rules.SentryAccessToken().RuleID:                       {7.6, 1.6, 4.6},
		rules.SentryOrgToken().RuleID:                          {7.6, 1.6, 4.6},
		rules.SentryUserToken().RuleID:                         {7.6, 1.6, 4.6},
		rules.SettlemintApplicationAccessToken().RuleID:        {9.4, 3.4, 6.4},
		rules.SettlemintPersonalAccessToken().RuleID:           {9.4, 3.4, 6.4},
		rules.SettlemintServiceAccessToken().RuleID:            {9.4, 3.4, 6.4},
		rules.ShippoAPIToken().RuleID:                          {9.4, 3.4, 6.4},
		rules.ShopifyAccessToken().RuleID:                      {7.6, 1.6, 4.6},
		rules.ShopifyCustomAccessToken().RuleID:                {7.6, 1.6, 4.6},
		rules.ShopifyPrivateAppAccessToken().RuleID:            {7.6, 1.6, 4.6},
		rules.ShopifySharedSecret().RuleID:                     {7.6, 1.6, 4.6},
		rules.SidekiqSecret().RuleID:                           {9.4, 3.4, 6.4},
		rules.SidekiqSensitiveUrl().RuleID:                     {9.4, 3.4, 6.4},
		rules.SlackBotToken().RuleID:                           {7.6, 1.6, 4.6},
		rules.SlackAppLevelToken().RuleID:                      {7.6, 1.6, 4.6},
		rules.SlackLegacyToken().RuleID:                        {7.6, 1.6, 4.6},
		rules.SlackUserToken().RuleID:                          {7.6, 1.6, 4.6},
		rules.SlackConfigurationToken().RuleID:                 {7.6, 1.6, 4.6},
		rules.SlackConfigurationRefreshToken().RuleID:          {7.6, 1.6, 4.6},
		rules.SlackLegacyBotToken().RuleID:                     {7.6, 1.6, 4.6},
		rules.SlackLegacyWorkspaceToken().RuleID:               {7.6, 1.6, 4.6},
		rules.SlackWebHookUrl().RuleID:                         {7.6, 1.6, 4.6},
		rules.StripeAccessToken().RuleID:                       {10, 7, 10},
		rules.SquareAccessToken().RuleID:                       {10, 7, 10},
		rules.SquareSpaceAccessToken().RuleID:                  {10, 5.2, 8.2},
		rules.SumoLogicAccessID().RuleID:                       {7.6, 1.6, 4.6},
		rules.SumoLogicAccessToken().RuleID:                    {7.6, 1.6, 4.6},
		rules.Snyk().RuleID:                                    {10, 7, 10},
		rules.TeamsWebhook().RuleID:                            {7.6, 1.6, 4.6},
		rules.TelegramBotToken().RuleID:                        {7.6, 1.6, 4.6},
		rules.TravisCIAccessToken().RuleID:                     {10, 5.2, 8.2},
		rules.Twilio().RuleID:                                  {7.6, 1.6, 4.6},
		rules.TwitchAPIToken().RuleID:                          {7.6, 1.6, 4.6},
		rules.TwitterAPIKey().RuleID:                           {7.6, 1.6, 4.6},
		rules.TwitterAPISecret().RuleID:                        {7.6, 1.6, 4.6},
		rules.TwitterAccessToken().RuleID:                      {7.6, 1.6, 4.6},
		rules.TwitterAccessSecret().RuleID:                     {7.6, 1.6, 4.6},
		rules.TwitterBearerToken().RuleID:                      {7.6, 1.6, 4.6},
		rules.Typeform().RuleID:                                {7.6, 1.6, 4.6},
		rules.VaultBatchToken().RuleID:                         {10, 7, 10},
		rules.VaultServiceToken().RuleID:                       {10, 7, 10},
		rules.YandexAPIKey().RuleID:                            {10, 5.2, 8.2},
		rules.YandexAWSAccessToken().RuleID:                    {10, 5.2, 8.2},
		rules.YandexAccessToken().RuleID:                       {10, 5.2, 8.2},
		rules.ZendeskSecretKey().RuleID:                        {9.4, 3.4, 6.4},
		specialRule.RuleID:                                     {10, 5.2, 8.2},
	}

	t.Run("Should get base risk score and cvss score", func(t *testing.T) {
		scorer := NewScorer(allRules, false)

		for _, rule := range allRules {
			expectedRuleScores := expectedCvssScores[rule.RuleID]
			baseRiskScore := GetBaseRiskScore(rule.ScoreParameters.Category, rule.ScoreParameters.RuleType)
			ruleBaseRiskScore := scorer.GetRulesBaseRiskScore(rule.RuleID)
			assert.Equal(t, ruleBaseRiskScore, baseRiskScore, "rule: %s", rule.RuleID)
			assert.Equal(t, expectedRuleScores[0], getCvssScore(baseRiskScore, secrets.ValidResult), "rule: %s", rule.RuleID)
			assert.Equal(t, expectedRuleScores[1], getCvssScore(baseRiskScore, secrets.InvalidResult), "rule: %s", rule.RuleID)
			assert.Equal(t, expectedRuleScores[2], getCvssScore(baseRiskScore, secrets.UnknownResult), "rule: %s", rule.RuleID)
		}
	})

	t.Run("Should get cvss score with validation", func(t *testing.T) {
		var allSecrets []*secrets.Secret
		for _, rule := range allRules {
			var secretValid, secretInvalid, secretUnknown secrets.Secret
			secretValid.RuleID = rule.RuleID
			secretValid.ValidationStatus = secrets.ValidResult
			secretInvalid.RuleID = rule.RuleID
			secretInvalid.ValidationStatus = secrets.InvalidResult
			secretUnknown.RuleID = rule.RuleID
			secretUnknown.ValidationStatus = secrets.UnknownResult
			allSecrets = append(allSecrets, &secretValid, &secretInvalid, &secretUnknown)
		}

		scorer := NewScorer(allRules, true)

		for _, secret := range allSecrets {
			expectedRuleScores := expectedCvssScores[secret.RuleID]
			validityIndex := getValidityIndex(secret.ValidationStatus)

			scorer.AssignScoreAndSeverity(secret)
			assert.Equal(t, expectedRuleScores[validityIndex], secret.CvssScore, "rule: %s", secret.RuleID)
		}
	})
	t.Run("Should get cvss score without validation", func(t *testing.T) {
		var allSecrets []*secrets.Secret
		for _, rule := range allRules {
			var secretValid, secretInvalid, secretUnknown secrets.Secret
			secretValid.RuleID = rule.RuleID
			secretValid.ValidationStatus = secrets.ValidResult
			secretInvalid.RuleID = rule.RuleID
			secretInvalid.ValidationStatus = secrets.InvalidResult
			secretUnknown.RuleID = rule.RuleID
			secretUnknown.ValidationStatus = secrets.UnknownResult
			allSecrets = append(allSecrets, &secretValid, &secretInvalid, &secretUnknown)
		}

		scorer := NewScorer(allRules, false)

		for _, secret := range allSecrets {
			expectedRuleScores := expectedCvssScores[secret.RuleID]
			unknownIndex := getValidityIndex(secrets.UnknownResult)

			scorer.AssignScoreAndSeverity(secret)
			assert.Equal(t, expectedRuleScores[unknownIndex], secret.CvssScore, "rule: %s", secret.RuleID)
		}
	})
}

func TestSecrets(t *testing.T) {
	secretsCases := []struct {
		name           string
		inputSecret    *secrets.Secret
		expectedSecret *secrets.Secret
	}{
		{
			name: "Valid secret with should have severity bumped from high to critical",
			inputSecret: &secrets.Secret{
				RuleID:           rules.CloudflareAPIKey().RuleID,
				ValidationStatus: secrets.ValidResult,
			},
			expectedSecret: &secrets.Secret{
				RuleID:           rules.CloudflareAPIKey().RuleID,
				Severity:         "Critical",
				ValidationStatus: secrets.ValidResult,
				CvssScore:        9.4,
			},
		},
		{
			name: "Unknown validity secret with should keep default severity for the rule (high)",
			inputSecret: &secrets.Secret{
				RuleID:           rules.CloudflareAPIKey().RuleID,
				ValidationStatus: secrets.UnknownResult,
			},
			expectedSecret: &secrets.Secret{
				RuleID:           rules.CloudflareAPIKey().RuleID,
				Severity:         "High",
				ValidationStatus: secrets.UnknownResult,
				CvssScore:        6.4,
			},
		},
		{
			name: "Invalid secret with should have severity bumped down from high to medium",
			inputSecret: &secrets.Secret{
				RuleID:           rules.CloudflareAPIKey().RuleID,
				ValidationStatus: secrets.InvalidResult,
			},
			expectedSecret: &secrets.Secret{
				RuleID:           rules.CloudflareAPIKey().RuleID,
				Severity:         "Medium",
				ValidationStatus: secrets.InvalidResult,
				CvssScore:        3.4,
			},
		},
	}

	allRules := rules.FilterRules([]string{}, []string{}, []string{})
	scorer := NewScorer(allRules, true)

	for _, tt := range secretsCases {
		t.Run(tt.name, func(t *testing.T) {
			scorer.AssignScoreAndSeverity(tt.inputSecret)
			assert.Equal(t, tt.expectedSecret, tt.inputSecret)
		})
	}

}

func getValidityIndex(validity secrets.ValidationResult) int {
	switch validity {
	case secrets.ValidResult:
		return 0
	case secrets.InvalidResult:
		return 1
	}
	return 2
}
