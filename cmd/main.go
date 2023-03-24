package cmd

import (
	"github.com/checkmarx/2ms/plugins"
	"github.com/checkmarx/2ms/reporting"
	"github.com/checkmarx/2ms/secrets"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "2ms",
	Short: "2ms Secrets Detection",
	Run:   execute,
}

var allPlugins = []plugins.IPlugin{
	&plugins.ConfluencePlugin{},
}

func initLog() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	ll, err := rootCmd.Flags().GetString("log-level")
	if err != nil {
		log.Fatal().Msg(err.Error())
	}
	switch strings.ToLower(ll) {
	case "trace":
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "err", "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case "fatal":
		zerolog.SetGlobalLevel(zerolog.FatalLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}

func Execute() {
	cobra.OnInitialize(initLog)
	rootCmd.Flags().BoolP("all", "", true, "scan all plugins")
	rootCmd.Flags().StringSlice("tags", []string{"all"}, "select rules to be applied")

	for _, plugin := range allPlugins {
		err := plugin.DefineCommandLineArgs(rootCmd)
		if err != nil {
			log.Fatal().Msg(err.Error())
		}
	}

	rootCmd.PersistentFlags().StringP("log-level", "", "info", "log level (trace, debug, info, warn, error, fatal)")

	if err := rootCmd.Execute(); err != nil {
		log.Fatal().Msg(err.Error())
	}
}

func validateTags(tags []string) {
	for _, tag := range tags {
		if !(strings.EqualFold(tag, "all") || strings.EqualFold(tag, secrets.TagApiKey) || strings.EqualFold(tag, secrets.TagClientId) ||
			strings.EqualFold(tag, secrets.TagClientSecret) || strings.EqualFold(tag, secrets.TagSecretKey) || strings.EqualFold(tag, secrets.TagAccessKey) ||
			strings.EqualFold(tag, secrets.TagAccessId) || strings.EqualFold(tag, secrets.TagApiToken) || strings.EqualFold(tag, secrets.TagAccessToken) ||
			strings.EqualFold(tag, secrets.TagRefreshToken) || strings.EqualFold(tag, secrets.TagPrivateKey) || strings.EqualFold(tag, secrets.TagPublicKey) ||
			strings.EqualFold(tag, secrets.TagEncryptionKey) || strings.EqualFold(tag, secrets.TagTriggerToken) || strings.EqualFold(tag, secrets.TagRegistrationToken) ||
			strings.EqualFold(tag, secrets.TagPassword) || strings.EqualFold(tag, secrets.TagUploadToken) || strings.EqualFold(tag, secrets.TagPublicSecret) ||
			strings.EqualFold(tag, secrets.TagSensitiveUrl) || strings.EqualFold(tag, secrets.TagWebhook)) {
			log.Fatal().Msgf(`invalid filter: %s`, tag)
		}
	}
}

func execute(cmd *cobra.Command, args []string) {
	tags, err := cmd.Flags().GetStringSlice("tags")
	if err != nil {
		log.Fatal().Msg(err.Error())
	}

	validateTags(tags)

	// -------------------------------------
	// Get content from plugins

	for _, plugin := range allPlugins {
		err := plugin.Initialize(cmd)
		if err != nil {
			log.Fatal().Msg(err.Error())
		}
	}

	items := make([]plugins.Item, 0)
	for _, plugin := range allPlugins {
		if !plugin.IsEnabled() {
			continue
		}

		pluginItems, err := plugin.GetItems()
		if err != nil {
			log.Fatal().Msg(err.Error())
		}
		items = append(items, *pluginItems...)
	}

	report := reporting.Report{}
	report.Results = make(map[string][]reporting.Secret)

	// -------------------------------------
	// Detect Secrets

	secrets := secrets.Init(tags)

	for _, item := range items {
		secrets := secrets.Detect(item.Content)
		if len(secrets) > 0 {
			report.TotalSecretsFound = report.TotalSecretsFound + len(secrets)
			report.Results[item.ID] = append(report.Results[item.ID], secrets...)
		}
	}
	report.TotalItemsScanned = len(items)

	// -------------------------------------
	// Show Report
	if len(items) > 0 {
		reporting.ShowReport(report)
	} else {
		log.Info().Msg("no plugin was loaded")
	}
}
