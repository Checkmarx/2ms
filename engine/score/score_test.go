package score_test

import (
	. "github.com/checkmarx/2ms/engine"
	"github.com/checkmarx/2ms/engine/rules"
	"github.com/checkmarx/2ms/engine/score"
	"github.com/checkmarx/2ms/lib/secrets"
	"github.com/stretchr/testify/assert"
	ruleConfig "github.com/zricethezav/gitleaks/v8/cmd/generate/config/rules"
	"sync"
	"testing"
)

func TestScore(t *testing.T) {
	specialRule := rules.HardcodedPassword()
	allRules := *rules.FilterRules([]string{}, []string{}, []string{specialRule.RuleID})

	engineConfig := EngineConfig{SpecialList: []string{specialRule.RuleID}}
	engine, err := Init(engineConfig)
	assert.NoError(t, err)

	expectedCvssScores := map[string][3]float64{ // ruleID -> Valid, Invalid, Unknown
		ruleConfig.AdafruitAPIKey().RuleID:                  {9.4, 3.4, 6.4},
		ruleConfig.AdobeClientID().RuleID:                   {5.8, 1, 2.8},
		ruleConfig.AdobeClientSecret().RuleID:               {9.4, 3.4, 6.4},
		ruleConfig.AgeSecretKey().RuleID:                    {10, 5.2, 8.2},
		ruleConfig.Airtable().RuleID:                        {10, 5.2, 8.2},
		ruleConfig.AlgoliaApiKey().RuleID:                   {7.6, 1.6, 4.6},
		ruleConfig.AlibabaAccessKey().RuleID:                {7.6, 1.6, 4.6},
		ruleConfig.AlibabaSecretKey().RuleID:                {10, 5.2, 8.2},
		ruleConfig.AsanaClientID().RuleID:                   {4, 1, 1},
		ruleConfig.AsanaClientSecret().RuleID:               {7.6, 1.6, 4.6},
		ruleConfig.Atlassian().RuleID:                       {9.4, 3.4, 6.4},
		ruleConfig.Authress().RuleID:                        {10, 7, 10},
		ruleConfig.AWS().RuleID:                             {10, 7, 10},
		ruleConfig.BitBucketClientID().RuleID:               {7.6, 1.6, 4.6},
		ruleConfig.BitBucketClientSecret().RuleID:           {10, 5.2, 8.2},
		ruleConfig.BittrexAccessKey().RuleID:                {10, 7, 10},
		ruleConfig.BittrexSecretKey().RuleID:                {10, 7, 10},
		ruleConfig.Beamer().RuleID:                          {7.6, 1.6, 4.6},
		ruleConfig.CodecovAccessToken().RuleID:              {10, 7, 10},
		ruleConfig.CoinbaseAccessToken().RuleID:             {10, 7, 10},
		ruleConfig.Clojars().RuleID:                         {10, 5.2, 8.2},
		ruleConfig.ConfluentAccessToken().RuleID:            {7.6, 1.6, 4.6},
		ruleConfig.ConfluentSecretKey().RuleID:              {7.6, 1.6, 4.6},
		ruleConfig.Contentful().RuleID:                      {9.4, 3.4, 6.4},
		ruleConfig.Databricks().RuleID:                      {9.4, 3.4, 6.4},
		ruleConfig.DatadogtokenAccessToken().RuleID:         {7.6, 1.6, 4.6},
		ruleConfig.DefinedNetworkingAPIToken().RuleID:       {9.4, 3.4, 6.4},
		ruleConfig.DigitalOceanPAT().RuleID:                 {10, 5.2, 8.2},
		ruleConfig.DigitalOceanOAuthToken().RuleID:          {10, 5.2, 8.2},
		ruleConfig.DigitalOceanRefreshToken().RuleID:        {10, 5.2, 8.2},
		ruleConfig.DiscordAPIToken().RuleID:                 {7.6, 1.6, 4.6},
		ruleConfig.DiscordClientID().RuleID:                 {4, 1, 1},
		ruleConfig.DiscordClientSecret().RuleID:             {7.6, 1.6, 4.6},
		ruleConfig.Doppler().RuleID:                         {10, 5.2, 8.2},
		ruleConfig.DropBoxAPISecret().RuleID:                {9.4, 3.4, 6.4},
		ruleConfig.DropBoxShortLivedAPIToken().RuleID:       {9.4, 3.4, 6.4},
		ruleConfig.DropBoxLongLivedAPIToken().RuleID:        {9.4, 3.4, 6.4},
		ruleConfig.DroneciAccessToken().RuleID:              {10, 5.2, 8.2},
		ruleConfig.Duffel().RuleID:                          {10, 5.2, 8.2},
		ruleConfig.Dynatrace().RuleID:                       {7.6, 1.6, 4.6},
		ruleConfig.EasyPost().RuleID:                        {9.4, 3.4, 6.4},
		ruleConfig.EasyPostTestAPI().RuleID:                 {9.4, 3.4, 6.4},
		ruleConfig.EtsyAccessToken().RuleID:                 {7.6, 1.6, 4.6},
		ruleConfig.Facebook().RuleID:                        {7.6, 1.6, 4.6},
		ruleConfig.FastlyAPIToken().RuleID:                  {9.4, 3.4, 6.4},
		ruleConfig.FinicityClientSecret().RuleID:            {10, 7, 10},
		ruleConfig.FinicityAPIToken().RuleID:                {10, 7, 10},
		ruleConfig.FlickrAccessToken().RuleID:               {9.4, 3.4, 6.4},
		ruleConfig.FinnhubAccessToken().RuleID:              {10, 7, 10},
		ruleConfig.FlutterwavePublicKey().RuleID:            {10, 7, 10},
		ruleConfig.FlutterwaveSecretKey().RuleID:            {10, 7, 10},
		ruleConfig.FlutterwaveEncKey().RuleID:               {10, 7, 10},
		ruleConfig.FrameIO().RuleID:                         {7.6, 1.6, 4.6},
		ruleConfig.FreshbooksAccessToken().RuleID:           {10, 7, 10},
		ruleConfig.GCPAPIKey().RuleID:                       {10, 5.2, 8.2},
		ruleConfig.GenericCredential().RuleID:               {10, 5.2, 8.2},
		ruleConfig.GitHubPat().RuleID:                       {10, 5.2, 8.2},
		ruleConfig.GitHubFineGrainedPat().RuleID:            {10, 5.2, 8.2},
		ruleConfig.GitHubOauth().RuleID:                     {10, 7, 10},
		ruleConfig.GitHubApp().RuleID:                       {10, 5.2, 8.2},
		ruleConfig.GitHubRefresh().RuleID:                   {10, 7, 10},
		ruleConfig.GitlabPat().RuleID:                       {10, 5.2, 8.2},
		ruleConfig.GitlabPipelineTriggerToken().RuleID:      {10, 5.2, 8.2},
		ruleConfig.GitlabRunnerRegistrationToken().RuleID:   {10, 5.2, 8.2},
		ruleConfig.GitterAccessToken().RuleID:               {7.6, 1.6, 4.6},
		ruleConfig.GoCardless().RuleID:                      {10, 7, 10},
		ruleConfig.GrafanaApiKey().RuleID:                   {7.6, 1.6, 4.6},
		ruleConfig.GrafanaCloudApiToken().RuleID:            {7.6, 1.6, 4.6},
		ruleConfig.GrafanaServiceAccountToken().RuleID:      {7.6, 1.6, 4.6},
		ruleConfig.Hashicorp().RuleID:                       {10, 5.2, 8.2},
		ruleConfig.HashicorpField().RuleID:                  {10, 5.2, 8.2},
		ruleConfig.Heroku().RuleID:                          {9.4, 3.4, 6.4},
		ruleConfig.HubSpot().RuleID:                         {7.6, 1.6, 4.6},
		ruleConfig.HuggingFaceAccessToken().RuleID:          {7.6, 1.6, 4.6},
		ruleConfig.HuggingFaceOrganizationApiToken().RuleID: {7.6, 1.6, 4.6},
		ruleConfig.InfracostAPIToken().RuleID:               {10, 7, 10},
		ruleConfig.Intercom().RuleID:                        {9.4, 3.4, 6.4},
		ruleConfig.JFrogAPIKey().RuleID:                     {10, 5.2, 8.2},
		ruleConfig.JFrogIdentityToken().RuleID:              {10, 5.2, 8.2},
		ruleConfig.JWT().RuleID:                             {10, 5.2, 8.2},
		ruleConfig.JWTBase64().RuleID:                       {10, 5.2, 8.2},
		ruleConfig.KrakenAccessToken().RuleID:               {10, 7, 10},
		ruleConfig.KucoinAccessToken().RuleID:               {10, 7, 10},
		ruleConfig.KucoinSecretKey().RuleID:                 {10, 7, 10},
		ruleConfig.LaunchDarklyAccessToken().RuleID:         {10, 5.2, 8.2},
		ruleConfig.LinearAPIToken().RuleID:                  {10, 5.2, 8.2},
		ruleConfig.LinearClientSecret().RuleID:              {10, 7, 10},
		ruleConfig.LinkedinClientID().RuleID:                {4, 1, 1},
		ruleConfig.LinkedinClientSecret().RuleID:            {7.6, 1.6, 4.6},
		ruleConfig.LobAPIToken().RuleID:                     {10, 5.2, 8.2},
		ruleConfig.LobPubAPIToken().RuleID:                  {10, 5.2, 8.2},
		ruleConfig.MailChimp().RuleID:                       {10, 5.2, 8.2},
		ruleConfig.MailGunPubAPIToken().RuleID:              {10, 5.2, 8.2},
		ruleConfig.MailGunPrivateAPIToken().RuleID:          {10, 5.2, 8.2},
		ruleConfig.MailGunSigningKey().RuleID:               {10, 5.2, 8.2},
		ruleConfig.MapBox().RuleID:                          {9.4, 3.4, 6.4},
		ruleConfig.MattermostAccessToken().RuleID:           {7.6, 1.6, 4.6},
		ruleConfig.MessageBirdAPIToken().RuleID:             {7.6, 1.6, 4.6},
		ruleConfig.MessageBirdClientID().RuleID:             {4, 1, 1},
		ruleConfig.NetlifyAccessToken().RuleID:              {10, 5.2, 8.2},
		ruleConfig.NewRelicUserID().RuleID:                  {4, 1, 1},
		ruleConfig.NewRelicUserKey().RuleID:                 {7.6, 1.6, 4.6},
		ruleConfig.NewRelicBrowserAPIKey().RuleID:           {7.6, 1.6, 4.6},
		ruleConfig.NPM().RuleID:                             {10, 5.2, 8.2},
		ruleConfig.NytimesAccessToken().RuleID:              {7.6, 1.6, 4.6},
		ruleConfig.OktaAccessToken().RuleID:                 {10, 7, 10},
		ruleConfig.OpenAI().RuleID:                          {7.6, 1.6, 4.6},
		rules.PlaidAccessID().RuleID:                        {9.4, 3.4, 6.4},
		ruleConfig.PlaidSecretKey().RuleID:                  {10, 7, 10},
		ruleConfig.PlaidAccessToken().RuleID:                {10, 7, 10},
		ruleConfig.PlanetScalePassword().RuleID:             {10, 5.2, 8.2},
		ruleConfig.PlanetScaleAPIToken().RuleID:             {10, 5.2, 8.2},
		ruleConfig.PlanetScaleOAuthToken().RuleID:           {10, 5.2, 8.2},
		ruleConfig.PostManAPI().RuleID:                      {10, 5.2, 8.2},
		ruleConfig.Prefect().RuleID:                         {10, 5.2, 8.2},
		rules.PrivateKey().RuleID:                           {10, 5.2, 8.2},
		ruleConfig.PulumiAPIToken().RuleID:                  {10, 5.2, 8.2},
		ruleConfig.PyPiUploadToken().RuleID:                 {10, 5.2, 8.2},
		ruleConfig.RapidAPIAccessToken().RuleID:             {10, 5.2, 8.2},
		ruleConfig.ReadMe().RuleID:                          {10, 5.2, 8.2},
		ruleConfig.RubyGemsAPIToken().RuleID:                {10, 5.2, 8.2},
		ruleConfig.ScalingoAPIToken().RuleID:                {10, 5.2, 8.2},
		ruleConfig.SendbirdAccessID().RuleID:                {4, 1, 1},
		ruleConfig.SendbirdAccessToken().RuleID:             {7.6, 1.6, 4.6},
		ruleConfig.SendGridAPIToken().RuleID:                {10, 5.2, 8.2},
		ruleConfig.SendInBlueAPIToken().RuleID:              {10, 5.2, 8.2},
		ruleConfig.SentryAccessToken().RuleID:               {7.6, 1.6, 4.6},
		ruleConfig.ShippoAPIToken().RuleID:                  {9.4, 3.4, 6.4},
		ruleConfig.ShopifyAccessToken().RuleID:              {7.6, 1.6, 4.6},
		ruleConfig.ShopifyCustomAccessToken().RuleID:        {7.6, 1.6, 4.6},
		ruleConfig.ShopifyPrivateAppAccessToken().RuleID:    {7.6, 1.6, 4.6},
		ruleConfig.ShopifySharedSecret().RuleID:             {7.6, 1.6, 4.6},
		ruleConfig.SidekiqSecret().RuleID:                   {9.4, 3.4, 6.4},
		ruleConfig.SidekiqSensitiveUrl().RuleID:             {9.4, 3.4, 6.4},
		ruleConfig.SlackBotToken().RuleID:                   {7.6, 1.6, 4.6},
		ruleConfig.SlackAppLevelToken().RuleID:              {7.6, 1.6, 4.6},
		ruleConfig.SlackLegacyToken().RuleID:                {7.6, 1.6, 4.6},
		ruleConfig.SlackUserToken().RuleID:                  {7.6, 1.6, 4.6},
		ruleConfig.SlackConfigurationToken().RuleID:         {7.6, 1.6, 4.6},
		ruleConfig.SlackConfigurationRefreshToken().RuleID:  {7.6, 1.6, 4.6},
		ruleConfig.SlackLegacyBotToken().RuleID:             {7.6, 1.6, 4.6},
		ruleConfig.SlackLegacyWorkspaceToken().RuleID:       {7.6, 1.6, 4.6},
		ruleConfig.SlackWebHookUrl().RuleID:                 {7.6, 1.6, 4.6},
		ruleConfig.StripeAccessToken().RuleID:               {10, 7, 10},
		ruleConfig.SquareAccessToken().RuleID:               {10, 7, 10},
		ruleConfig.SquareSpaceAccessToken().RuleID:          {10, 5.2, 8.2},
		ruleConfig.SumoLogicAccessID().RuleID:               {7.6, 1.6, 4.6},
		ruleConfig.SumoLogicAccessToken().RuleID:            {7.6, 1.6, 4.6},
		ruleConfig.Snyk().RuleID:                            {10, 7, 10},
		ruleConfig.TeamsWebhook().RuleID:                    {7.6, 1.6, 4.6},
		ruleConfig.TelegramBotToken().RuleID:                {7.6, 1.6, 4.6},
		ruleConfig.TravisCIAccessToken().RuleID:             {10, 5.2, 8.2},
		ruleConfig.Twilio().RuleID:                          {7.6, 1.6, 4.6},
		ruleConfig.TwitchAPIToken().RuleID:                  {7.6, 1.6, 4.6},
		ruleConfig.TwitterAPIKey().RuleID:                   {7.6, 1.6, 4.6},
		ruleConfig.TwitterAPISecret().RuleID:                {7.6, 1.6, 4.6},
		ruleConfig.TwitterAccessToken().RuleID:              {7.6, 1.6, 4.6},
		ruleConfig.TwitterAccessSecret().RuleID:             {7.6, 1.6, 4.6},
		ruleConfig.TwitterBearerToken().RuleID:              {7.6, 1.6, 4.6},
		ruleConfig.Typeform().RuleID:                        {7.6, 1.6, 4.6},
		ruleConfig.VaultBatchToken().RuleID:                 {10, 7, 10},
		rules.VaultServiceToken().RuleID:                    {10, 7, 10},
		ruleConfig.YandexAPIKey().RuleID:                    {10, 5.2, 8.2},
		ruleConfig.YandexAWSAccessToken().RuleID:            {10, 5.2, 8.2},
		ruleConfig.YandexAccessToken().RuleID:               {10, 5.2, 8.2},
		ruleConfig.ZendeskSecretKey().RuleID:                {9.4, 3.4, 6.4},
		rules.AuthenticatedURL().RuleID:                     {10, 5.2, 8.2},
		specialRule.RuleID:                                  {10, 5.2, 8.2},
	}
	for _, rule := range allRules {
		expectedRuleScores := expectedCvssScores[rule.Rule.RuleID]
		baseRiskScore := score.GetBaseRiskScore(rule.ScoreParameters.Category, rule.ScoreParameters.RuleType)
		ruleBaseRiskScore := engine.GetRuleBaseRiskScore(rule.Rule.RuleID)
		assert.Equal(t, ruleBaseRiskScore, baseRiskScore, "rule: %s", rule.Rule.RuleID)
		assert.Equal(t, expectedRuleScores[0], score.GetCvssScore(baseRiskScore, secrets.ValidResult), "rule: %s", rule.Rule.RuleID)
		assert.Equal(t, expectedRuleScores[1], score.GetCvssScore(baseRiskScore, secrets.InvalidResult), "rule: %s", rule.Rule.RuleID)
		assert.Equal(t, expectedRuleScores[2], score.GetCvssScore(baseRiskScore, secrets.UnknownResult), "rule: %s", rule.Rule.RuleID)
	}

	var allSecrets []*secrets.Secret
	for _, rule := range allRules {
		var secretValid, secretInvalid, secretUnknown secrets.Secret
		secretValid.RuleID = rule.Rule.RuleID
		secretValid.ValidationStatus = secrets.ValidResult
		secretInvalid.RuleID = rule.Rule.RuleID
		secretInvalid.ValidationStatus = secrets.InvalidResult
		secretUnknown.RuleID = rule.Rule.RuleID
		secretUnknown.ValidationStatus = secrets.UnknownResult
		allSecrets = append(allSecrets, &secretValid, &secretInvalid, &secretUnknown)
	}
	for _, secret := range allSecrets {
		var wg sync.WaitGroup
		wg.Add(2)
		expectedRuleScores := expectedCvssScores[secret.RuleID]
		validityIndex := getValidityIndex(secret.ValidationStatus)
		unknownIndex := getValidityIndex(secrets.UnknownResult)
		engine.Score(secret, true, &wg)
		assert.Equal(t, expectedRuleScores[validityIndex], secret.CvssScore, "rule: %s", secret.RuleID)
		engine.Score(secret, false, &wg)
		assert.Equal(t, expectedRuleScores[unknownIndex], secret.CvssScore, "rule: %s", secret.RuleID)
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
