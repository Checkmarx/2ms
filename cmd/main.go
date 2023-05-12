package cmd

import (
	"os"
	"strings"
	"sync"
	"time"

	"github.com/checkmarx/2ms/plugins"
	"github.com/checkmarx/2ms/reporting"
	"github.com/checkmarx/2ms/secrets"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const timeSleepInterval = 50
const reportPath = "report-path"

var rootCmd = &cobra.Command{
	Use:     "2ms",
	Short:   "2ms Secrets Detection",
	Run:     execute,
	Version: Version,
}

var Version = ""

var allPlugins = []plugins.IPlugin{
	&plugins.ConfluencePlugin{},
	&plugins.DiscordPlugin{},
	&plugins.RepositoryPlugin{},
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
	rootCmd.Flags().StringP(reportPath, "r", "", "path to generate report file")

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
	reportPath, _ := cmd.Flags().GetString("report-path")
	if err != nil {
		log.Fatal().Msg(err.Error())
	}

	validateTags(tags)

	secrets := secrets.Init(tags)
	report := reporting.Init()

	var itemsChannel = make(chan plugins.Item)
	var secretsChannel = make(chan reporting.Secret)
	var errorsChannel = make(chan error)

	var wg sync.WaitGroup

	cfg := config.LoadConfig("2ms", Version)

	// -------------------------------------
	// Get content from plugins
	pluginsInitialized := 0
	for _, plugin := range allPlugins {
		err := plugin.Initialize(cmd)
		if err != nil {
			log.Error().Msg(err.Error())
			continue
		}
		pluginsInitialized += 1
	}

	if pluginsInitialized == 0 {
		log.Fatal().Msg("no scan plugin initialized. At least one plugin must be initialized to proceed. Stopping")
		os.Exit(1)
	}

	for _, plugin := range allPlugins {
		if !plugin.IsEnabled() {
			continue
		}

		wg.Add(1)
		go plugin.GetItems(itemsChannel, errorsChannel, &wg)
	}

	go func() {
		for {
			select {
			case item := <-itemsChannel:
				report.TotalItemsScanned++
				wg.Add(1)
				go secrets.Detect(secretsChannel, item, &wg)
			case secret := <-secretsChannel:
				report.TotalSecretsFound++
				report.Results[secret.Source] = append(report.Results[secret.Source], secret)
			case err, ok := <-errorsChannel:
				if !ok {
					return
				}
				log.Fatal().Msg(err.Error())
			}
		}
	}()
	wg.Wait()

	// Wait for last secret to be added to report
	time.Sleep(time.Millisecond * timeSleepInterval)

	// -------------------------------------
	// Show Report
	if report.TotalItemsScanned > 0 {
		report.ShowReport()
		if reportPath != "" {
			err := report.Write(reportPath, cfg)
			if err != nil {
				log.Error().Msgf("Failed to create sarif file report with error: %s", err)
			}
		}
	} else {
		log.Error().Msg("Scan completed with empty content")
		os.Exit(0)
	}

	if report.TotalSecretsFound > 0 {
		os.Exit(1)
	} else {
		os.Exit(0)
	}

}
