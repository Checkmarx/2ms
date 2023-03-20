package cmd

import (
	"github.com/checkmarx/2ms/plugins"
	"github.com/checkmarx/2ms/reporting"
	"github.com/checkmarx/2ms/wrapper"
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
	rootCmd.Flags().StringSlice("rules", []string{"all"}, "select rules to be applied")

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

func isValidFilter(rulesFilter []string) bool {
	for _, filter := range rulesFilter {
		if !(strings.EqualFold(filter, "all") || strings.EqualFold(filter, "token") || strings.EqualFold(filter, "key") || strings.EqualFold(filter, "id")) {
			return false
		}
	}
	return true
}

func execute(cmd *cobra.Command, args []string) {
	rulesFilter, err := cmd.Flags().GetStringSlice("rules")
	if err != nil {
		log.Fatal().Msg(err.Error())
	}

	if !isValidFilter(rulesFilter) {
		log.Fatal().Msg(`rules filter allowed: "all", "token", "id", "key"`) //missing input from Bryant
	}

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

	wrap := wrapper.NewWrapper(rulesFilter)

	for _, item := range items {
		secrets := wrap.Detect(item.Content)
		report.Results[item.ID] = append(report.Results[item.ID], secrets...)
	}
	report.TotalItemsScanned = len(items)

	// -------------------------------------
	// Show Report

	reporting.ShowReport(report)
}
