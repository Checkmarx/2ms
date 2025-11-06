package score

import (
	"testing"

	"github.com/checkmarx/2ms/v4/engine/rules"
	"github.com/checkmarx/2ms/v4/engine/rules/ruledefine"
	"github.com/checkmarx/2ms/v4/lib/secrets"
	"github.com/stretchr/testify/assert"
)

func TestScore(t *testing.T) {
	specialRule := ruledefine.HardcodedPassword()
	allRules := rules.FilterRules([]string{"grafana-service-account-token"}, []string{}, []string{specialRule.RuleName}, nil, false)

	expectedCvssScores := map[string][3]float64{ // ruleID -> Valid, Invalid, Unknown
		ruledefine.AdafruitAPIKey().RuleID:                          {9.4, 3.4, 6.4},
		ruledefine.AdobeClientID().RuleID:                           {5.8, 1, 2.8},
		ruledefine.AdobeClientSecret().RuleID:                       {9.4, 3.4, 6.4},
		ruledefine.AgeSecretKey().RuleID:                            {10, 5.2, 8.2},
		ruledefine.Airtable().RuleID:                                {10, 5.2, 8.2},
		ruledefine.AlgoliaApiKey().RuleID:                           {7.6, 1.6, 4.6},
		ruledefine.AlibabaAccessKey().RuleID:                        {7.6, 1.6, 4.6},
		ruledefine.AlibabaSecretKey().RuleID:                        {10, 5.2, 8.2},
		ruledefine.AnthropicAdminApiKey().RuleID:                    {7.6, 1.6, 4.6},
		ruledefine.AnthropicApiKey().RuleID:                         {7.6, 1.6, 4.6},
		ruledefine.AsanaClientID().RuleID:                           {4, 1, 1},
		ruledefine.AsanaClientSecret().RuleID:                       {7.6, 1.6, 4.6},
		ruledefine.Atlassian().RuleID:                               {9.4, 3.4, 6.4},
		ruledefine.AuthenticatedURL().RuleID:                        {10, 5.2, 8.2},
		ruledefine.Authress().RuleID:                                {10, 7, 10},
		ruledefine.AWS().RuleID:                                     {10, 7, 10},
		ruledefine.AzureActiveDirectoryClientSecret().RuleID:        {10, 7, 10},
		ruledefine.BitBucketClientID().RuleID:                       {7.6, 1.6, 4.6},
		ruledefine.BitBucketClientSecret().RuleID:                   {10, 5.2, 8.2},
		ruledefine.BittrexAccessKey().RuleID:                        {10, 7, 10},
		ruledefine.BittrexSecretKey().RuleID:                        {10, 7, 10},
		ruledefine.Beamer().RuleID:                                  {7.6, 1.6, 4.6},
		ruledefine.CodecovAccessToken().RuleID:                      {10, 7, 10},
		ruledefine.CoinbaseAccessToken().RuleID:                     {10, 7, 10},
		ruledefine.ClickHouseCloud().RuleID:                         {10, 5.2, 8.2},
		ruledefine.Clojars().RuleID:                                 {10, 5.2, 8.2},
		ruledefine.CloudflareAPIKey().RuleID:                        {9.4, 3.4, 6.4},
		ruledefine.CloudflareGlobalAPIKey().RuleID:                  {9.4, 3.4, 6.4},
		ruledefine.CloudflareOriginCAKey().RuleID:                   {9.4, 3.4, 6.4},
		ruledefine.CohereAPIToken().RuleID:                          {7.6, 1.6, 4.6},
		ruledefine.ConfluentAccessToken().RuleID:                    {7.6, 1.6, 4.6},
		ruledefine.ConfluentSecretKey().RuleID:                      {7.6, 1.6, 4.6},
		ruledefine.Contentful().RuleID:                              {9.4, 3.4, 6.4},
		ruledefine.CurlBasicAuth().RuleID:                           {9.4, 3.4, 6.4},
		ruledefine.CurlHeaderAuth().RuleID:                          {9.4, 3.4, 6.4},
		ruledefine.Databricks().RuleID:                              {9.4, 3.4, 6.4},
		ruledefine.DatadogtokenAccessToken().RuleID:                 {7.6, 1.6, 4.6},
		ruledefine.DefinedNetworkingAPIToken().RuleID:               {9.4, 3.4, 6.4},
		ruledefine.DigitalOceanPAT().RuleID:                         {10, 5.2, 8.2},
		ruledefine.DigitalOceanOAuthToken().RuleID:                  {10, 5.2, 8.2},
		ruledefine.DigitalOceanRefreshToken().RuleID:                {10, 5.2, 8.2},
		ruledefine.DiscordAPIToken().RuleID:                         {7.6, 1.6, 4.6},
		ruledefine.DiscordClientID().RuleID:                         {4, 1, 1},
		ruledefine.DiscordClientSecret().RuleID:                     {7.6, 1.6, 4.6},
		ruledefine.Doppler().RuleID:                                 {10, 5.2, 8.2},
		ruledefine.DropBoxAPISecret().RuleID:                        {9.4, 3.4, 6.4},
		ruledefine.DropBoxShortLivedAPIToken().RuleID:               {9.4, 3.4, 6.4},
		ruledefine.DropBoxLongLivedAPIToken().RuleID:                {9.4, 3.4, 6.4},
		ruledefine.DroneciAccessToken().RuleID:                      {10, 5.2, 8.2},
		ruledefine.Duffel().RuleID:                                  {10, 5.2, 8.2},
		ruledefine.Dynatrace().RuleID:                               {7.6, 1.6, 4.6},
		ruledefine.EasyPost().RuleID:                                {9.4, 3.4, 6.4},
		ruledefine.EasyPostTestAPI().RuleID:                         {9.4, 3.4, 6.4},
		ruledefine.EtsyAccessToken().RuleID:                         {7.6, 1.6, 4.6},
		ruledefine.FacebookAccessToken().RuleID:                     {7.6, 1.6, 4.6},
		ruledefine.FacebookPageAccessToken().RuleID:                 {7.6, 1.6, 4.6},
		ruledefine.FacebookSecret().RuleID:                          {7.6, 1.6, 4.6},
		ruledefine.FastlyAPIToken().RuleID:                          {9.4, 3.4, 6.4},
		ruledefine.FinicityClientSecret().RuleID:                    {10, 7, 10},
		ruledefine.FinicityAPIToken().RuleID:                        {10, 7, 10},
		ruledefine.FlickrAccessToken().RuleID:                       {9.4, 3.4, 6.4},
		ruledefine.FinnhubAccessToken().RuleID:                      {10, 7, 10},
		ruledefine.FlutterwavePublicKey().RuleID:                    {10, 7, 10},
		ruledefine.FlutterwaveSecretKey().RuleID:                    {10, 7, 10},
		ruledefine.FlutterwaveEncKey().RuleID:                       {10, 7, 10},
		ruledefine.FlyIOAccessToken().RuleID:                        {10, 5.2, 8.2},
		ruledefine.FrameIO().RuleID:                                 {7.6, 1.6, 4.6},
		ruledefine.Freemius().RuleID:                                {7.6, 1.6, 4.6},
		ruledefine.FreshbooksAccessToken().RuleID:                   {10, 7, 10},
		ruledefine.GCPAPIKey().RuleID:                               {10, 5.2, 8.2},
		ruledefine.GenericCredential().RuleID:                       {10, 5.2, 8.2},
		ruledefine.GitHubPat().RuleID:                               {10, 5.2, 8.2},
		ruledefine.GitHubFineGrainedPat().RuleID:                    {10, 5.2, 8.2},
		ruledefine.GitHubOauth().RuleID:                             {10, 7, 10},
		ruledefine.GitHubApp().RuleID:                               {10, 5.2, 8.2},
		ruledefine.GitHubRefresh().RuleID:                           {10, 7, 10},
		ruledefine.GitlabCiCdJobToken().RuleID:                      {10, 5.2, 8.2},
		ruledefine.GitlabDeployToken().RuleID:                       {10, 5.2, 8.2},
		ruledefine.GitlabFeatureFlagClientToken().RuleID:            {10, 5.2, 8.2},
		ruledefine.GitlabFeedToken().RuleID:                         {10, 5.2, 8.2},
		ruledefine.GitlabIncomingMailToken().RuleID:                 {10, 5.2, 8.2},
		ruledefine.GitlabKubernetesAgentToken().RuleID:              {10, 5.2, 8.2},
		ruledefine.GitlabOauthAppSecret().RuleID:                    {10, 5.2, 8.2},
		ruledefine.GitlabPat().RuleID:                               {10, 5.2, 8.2},
		ruledefine.GitlabPatRoutable().RuleID:                       {10, 5.2, 8.2},
		ruledefine.GitlabPipelineTriggerToken().RuleID:              {10, 5.2, 8.2},
		ruledefine.GitlabRunnerRegistrationToken().RuleID:           {10, 5.2, 8.2},
		ruledefine.GitlabRunnerAuthenticationToken().RuleID:         {10, 5.2, 8.2},
		ruledefine.GitlabRunnerAuthenticationTokenRoutable().RuleID: {10, 5.2, 8.2},
		ruledefine.GitlabScimToken().RuleID:                         {10, 5.2, 8.2},
		ruledefine.GitlabSessionCookie().RuleID:                     {10, 5.2, 8.2},
		ruledefine.GitterAccessToken().RuleID:                       {7.6, 1.6, 4.6},
		ruledefine.GoCardless().RuleID:                              {10, 7, 10},
		ruledefine.GrafanaApiKey().RuleID:                           {7.6, 1.6, 4.6},
		ruledefine.GrafanaCloudApiToken().RuleID:                    {7.6, 1.6, 4.6},
		ruledefine.GrafanaServiceAccountToken().RuleID:              {7.6, 1.6, 4.6},
		ruledefine.HashiCorpTerraform().RuleID:                      {10, 5.2, 8.2},
		ruledefine.HashicorpField().RuleID:                          {10, 5.2, 8.2},
		ruledefine.Heroku().RuleID:                                  {9.4, 3.4, 6.4},
		ruledefine.HerokuV2().RuleID:                                {9.4, 3.4, 6.4},
		ruledefine.HubSpot().RuleID:                                 {7.6, 1.6, 4.6},
		ruledefine.HuggingFaceAccessToken().RuleID:                  {7.6, 1.6, 4.6},
		ruledefine.HuggingFaceOrganizationApiToken().RuleID:         {7.6, 1.6, 4.6},
		ruledefine.InfracostAPIToken().RuleID:                       {10, 7, 10},
		ruledefine.Intercom().RuleID:                                {9.4, 3.4, 6.4},
		ruledefine.Intra42ClientSecret().RuleID:                     {10, 5.2, 8.2},
		ruledefine.JFrogAPIKey().RuleID:                             {10, 5.2, 8.2},
		ruledefine.JFrogIdentityToken().RuleID:                      {10, 5.2, 8.2},
		ruledefine.JWT().RuleID:                                     {10, 5.2, 8.2},
		ruledefine.JWTBase64().RuleID:                               {10, 5.2, 8.2},
		ruledefine.KrakenAccessToken().RuleID:                       {10, 7, 10},
		ruledefine.KubernetesSecret().RuleID:                        {10, 5.2, 8.2},
		ruledefine.KucoinAccessToken().RuleID:                       {10, 7, 10},
		ruledefine.KucoinSecretKey().RuleID:                         {10, 7, 10},
		ruledefine.LaunchDarklyAccessToken().RuleID:                 {9.4, 3.4, 6.4},
		ruledefine.LinearAPIToken().RuleID:                          {10, 5.2, 8.2},
		ruledefine.LinearClientSecret().RuleID:                      {10, 7, 10},
		ruledefine.LinkedinClientID().RuleID:                        {4, 1, 1},
		ruledefine.LinkedinClientSecret().RuleID:                    {7.6, 1.6, 4.6},
		ruledefine.LobAPIToken().RuleID:                             {10, 5.2, 8.2},
		ruledefine.LobPubAPIToken().RuleID:                          {10, 5.2, 8.2},
		ruledefine.MailChimp().RuleID:                               {10, 5.2, 8.2},
		ruledefine.MailGunPubAPIToken().RuleID:                      {10, 5.2, 8.2},
		ruledefine.MailGunPrivateAPIToken().RuleID:                  {10, 5.2, 8.2},
		ruledefine.MailGunSigningKey().RuleID:                       {10, 5.2, 8.2},
		ruledefine.MapBox().RuleID:                                  {9.4, 3.4, 6.4},
		ruledefine.MattermostAccessToken().RuleID:                   {7.6, 1.6, 4.6},
		ruledefine.MaxMindLicenseKey().RuleID:                       {9.4, 3.4, 6.4},
		ruledefine.Meraki().RuleID:                                  {9.4, 3.4, 6.4},
		ruledefine.MessageBirdAPIToken().RuleID:                     {7.6, 1.6, 4.6},
		ruledefine.MessageBirdClientID().RuleID:                     {4, 1, 1},
		ruledefine.NetlifyAccessToken().RuleID:                      {10, 5.2, 8.2},
		ruledefine.NewRelicUserID().RuleID:                          {4, 1, 1},
		ruledefine.NewRelicUserKey().RuleID:                         {7.6, 1.6, 4.6},
		ruledefine.NewRelicBrowserAPIKey().RuleID:                   {7.6, 1.6, 4.6},
		ruledefine.NewRelicInsertKey().RuleID:                       {7.6, 1.6, 4.6},
		ruledefine.Notion().RuleID:                                  {9.4, 3.4, 6.4},
		ruledefine.NPM().RuleID:                                     {10, 5.2, 8.2},
		ruledefine.NugetConfigPassword().RuleID:                     {10, 5.2, 8.2},
		ruledefine.OctopusDeployApiKey().RuleID:                     {10, 5.2, 8.2},
		ruledefine.NytimesAccessToken().RuleID:                      {7.6, 1.6, 4.6},
		ruledefine.OktaAccessToken().RuleID:                         {10, 7, 10},
		ruledefine.OnePasswordSecretKey().RuleID:                    {10, 7, 10},
		ruledefine.OnePasswordServiceAccountToken().RuleID:          {10, 7, 10},
		ruledefine.OpenAI().RuleID:                                  {7.6, 1.6, 4.6},
		ruledefine.OpenshiftUserToken().RuleID:                      {10, 5.2, 8.2},
		ruledefine.PerplexityAPIKey().RuleID:                        {7.6, 1.6, 4.6},
		ruledefine.PlaidAccessID().RuleID:                           {9.4, 3.4, 6.4},
		ruledefine.PlaidSecretKey().RuleID:                          {10, 7, 10},
		ruledefine.PlaidAccessToken().RuleID:                        {10, 7, 10},
		ruledefine.PlanetScalePassword().RuleID:                     {10, 5.2, 8.2},
		ruledefine.PlanetScaleAPIToken().RuleID:                     {10, 5.2, 8.2},
		ruledefine.PlanetScaleOAuthToken().RuleID:                   {10, 5.2, 8.2},
		ruledefine.PostManAPI().RuleID:                              {10, 5.2, 8.2},
		ruledefine.Prefect().RuleID:                                 {10, 5.2, 8.2},
		ruledefine.PrivateAIToken().RuleID:                          {7.6, 1.6, 4.6},
		ruledefine.PrivateKey().RuleID:                              {10, 5.2, 8.2},
		ruledefine.PulumiAPIToken().RuleID:                          {10, 5.2, 8.2},
		ruledefine.PyPiUploadToken().RuleID:                         {10, 5.2, 8.2},
		ruledefine.RapidAPIAccessToken().RuleID:                     {10, 5.2, 8.2},
		ruledefine.ReadMe().RuleID:                                  {10, 5.2, 8.2},
		ruledefine.RubyGemsAPIToken().RuleID:                        {10, 5.2, 8.2},
		ruledefine.ScalingoAPIToken().RuleID:                        {10, 5.2, 8.2},
		ruledefine.SendbirdAccessID().RuleID:                        {4, 1, 1},
		ruledefine.SendbirdAccessToken().RuleID:                     {7.6, 1.6, 4.6},
		ruledefine.SendGridAPIToken().RuleID:                        {10, 5.2, 8.2},
		ruledefine.SendInBlueAPIToken().RuleID:                      {10, 5.2, 8.2},
		ruledefine.SentryAccessToken().RuleID:                       {7.6, 1.6, 4.6},
		ruledefine.SentryOrgToken().RuleID:                          {7.6, 1.6, 4.6},
		ruledefine.SentryUserToken().RuleID:                         {7.6, 1.6, 4.6},
		ruledefine.SettlemintApplicationAccessToken().RuleID:        {9.4, 3.4, 6.4},
		ruledefine.SettlemintPersonalAccessToken().RuleID:           {9.4, 3.4, 6.4},
		ruledefine.SettlemintServiceAccessToken().RuleID:            {9.4, 3.4, 6.4},
		ruledefine.ShippoAPIToken().RuleID:                          {9.4, 3.4, 6.4},
		ruledefine.ShopifyAccessToken().RuleID:                      {7.6, 1.6, 4.6},
		ruledefine.ShopifyCustomAccessToken().RuleID:                {7.6, 1.6, 4.6},
		ruledefine.ShopifyPrivateAppAccessToken().RuleID:            {7.6, 1.6, 4.6},
		ruledefine.ShopifySharedSecret().RuleID:                     {7.6, 1.6, 4.6},
		ruledefine.SidekiqSecret().RuleID:                           {9.4, 3.4, 6.4},
		ruledefine.SidekiqSensitiveUrl().RuleID:                     {9.4, 3.4, 6.4},
		ruledefine.SlackBotToken().RuleID:                           {7.6, 1.6, 4.6},
		ruledefine.SlackAppLevelToken().RuleID:                      {7.6, 1.6, 4.6},
		ruledefine.SlackLegacyToken().RuleID:                        {7.6, 1.6, 4.6},
		ruledefine.SlackUserToken().RuleID:                          {7.6, 1.6, 4.6},
		ruledefine.SlackConfigurationToken().RuleID:                 {7.6, 1.6, 4.6},
		ruledefine.SlackConfigurationRefreshToken().RuleID:          {7.6, 1.6, 4.6},
		ruledefine.SlackLegacyBotToken().RuleID:                     {7.6, 1.6, 4.6},
		ruledefine.SlackLegacyWorkspaceToken().RuleID:               {7.6, 1.6, 4.6},
		ruledefine.SlackWebHookUrl().RuleID:                         {7.6, 1.6, 4.6},
		ruledefine.StripeAccessToken().RuleID:                       {10, 7, 10},
		ruledefine.SquareAccessToken().RuleID:                       {10, 7, 10},
		ruledefine.SquareSpaceAccessToken().RuleID:                  {10, 5.2, 8.2},
		ruledefine.SumoLogicAccessID().RuleID:                       {7.6, 1.6, 4.6},
		ruledefine.SumoLogicAccessToken().RuleID:                    {7.6, 1.6, 4.6},
		ruledefine.Snyk().RuleID:                                    {10, 7, 10},
		ruledefine.TeamsWebhook().RuleID:                            {7.6, 1.6, 4.6},
		ruledefine.TelegramBotToken().RuleID:                        {7.6, 1.6, 4.6},
		ruledefine.TravisCIAccessToken().RuleID:                     {10, 5.2, 8.2},
		ruledefine.Twilio().RuleID:                                  {7.6, 1.6, 4.6},
		ruledefine.TwitchAPIToken().RuleID:                          {7.6, 1.6, 4.6},
		ruledefine.TwitterAPIKey().RuleID:                           {7.6, 1.6, 4.6},
		ruledefine.TwitterAPISecret().RuleID:                        {7.6, 1.6, 4.6},
		ruledefine.TwitterAccessToken().RuleID:                      {7.6, 1.6, 4.6},
		ruledefine.TwitterAccessSecret().RuleID:                     {7.6, 1.6, 4.6},
		ruledefine.TwitterBearerToken().RuleID:                      {7.6, 1.6, 4.6},
		ruledefine.Typeform().RuleID:                                {7.6, 1.6, 4.6},
		ruledefine.VaultBatchToken().RuleID:                         {10, 7, 10},
		ruledefine.VaultServiceToken().RuleID:                       {10, 7, 10},
		ruledefine.YandexAPIKey().RuleID:                            {10, 5.2, 8.2},
		ruledefine.YandexAWSAccessToken().RuleID:                    {10, 5.2, 8.2},
		ruledefine.YandexAccessToken().RuleID:                       {10, 5.2, 8.2},
		ruledefine.ZendeskSecretKey().RuleID:                        {9.4, 3.4, 6.4},
		specialRule.RuleID:                                          {10, 5.2, 8.2},
	}

	t.Run("Should get base risk score and cvss score", func(t *testing.T) {
		scorer := NewScorer(allRules, false)

		for _, rule := range allRules {
			expectedRuleScores := expectedCvssScores[rule.RuleID]
			baseRiskScore := GetBaseRiskScore(rule.ScoreParameters.Category, rule.ScoreParameters.RuleType)
			ruleBaseRiskScore := scorer.GetRulesBaseRiskScore(rule.RuleID)
			assert.Equal(t, ruleBaseRiskScore, baseRiskScore, "rule: %s", rule.RuleName)
			assert.Equal(t, expectedRuleScores[0], getCvssScore(baseRiskScore, secrets.ValidResult), "rule: %s", rule.RuleName)
			assert.Equal(t, expectedRuleScores[1], getCvssScore(baseRiskScore, secrets.InvalidResult), "rule: %s", rule.RuleName)
			assert.Equal(t, expectedRuleScores[2], getCvssScore(baseRiskScore, secrets.UnknownResult), "rule: %s", rule.RuleName)
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
				RuleID:           ruledefine.CloudflareAPIKey().RuleID,
				ValidationStatus: secrets.ValidResult,
			},
			expectedSecret: &secrets.Secret{
				RuleID:           ruledefine.CloudflareAPIKey().RuleID,
				Severity:         "Critical",
				ValidationStatus: secrets.ValidResult,
				CvssScore:        9.4,
			},
		},
		{
			name: "Unknown validity secret with should keep default severity for the rule (high)",
			inputSecret: &secrets.Secret{
				RuleID:           ruledefine.CloudflareAPIKey().RuleID,
				ValidationStatus: secrets.UnknownResult,
			},
			expectedSecret: &secrets.Secret{
				RuleID:           ruledefine.CloudflareAPIKey().RuleID,
				Severity:         "High",
				ValidationStatus: secrets.UnknownResult,
				CvssScore:        6.4,
			},
		},
		{
			name: "Invalid secret with should have severity bumped down from high to medium",
			inputSecret: &secrets.Secret{
				RuleID:           ruledefine.CloudflareAPIKey().RuleID,
				ValidationStatus: secrets.InvalidResult,
			},
			expectedSecret: &secrets.Secret{
				RuleID:           ruledefine.CloudflareAPIKey().RuleID,
				Severity:         "Medium",
				ValidationStatus: secrets.InvalidResult,
				CvssScore:        3.4,
			},
		},
	}

	allRules := rules.FilterRules([]string{}, []string{}, []string{}, nil, false)
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
