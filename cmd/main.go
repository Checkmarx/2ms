package cmd

import (
	"fmt"
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
	Run:   runDetection,
}

func init() {
	cobra.OnInitialize(initLog)
	rootCmd.Flags().BoolP("all", "a", true, "scan all plugins")

	// TODO decouple and move to plugin level
	rootCmd.Flags().StringP("confluence", "", "", "scan confluence url")
	rootCmd.Flags().StringP("confluence-spaces", "", "", "confluence spaces")
	rootCmd.Flags().StringP("confluence-user", "", "", "confluence username or email")
	rootCmd.Flags().StringP("confluence-token", "", "", "confluence token")

	rootCmd.Flags().BoolP("all-rules", "r", true, "use all rules")
	rootCmd.PersistentFlags().StringP("log-level", "l", "info", "log level (trace, debug, info, warn, error, fatal)")
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
	if err := rootCmd.Execute(); err != nil {
		log.Fatal().Msg(err.Error())
	}
}

func runDetection(cmd *cobra.Command, args []string) {
	allRules, err := cmd.Flags().GetBool("all-rules")
	if err != nil {
		log.Fatal().Msg(err.Error())
	}

	// Get desired plugins content
	plugins := plugins.NewPlugins()

	//allPlugins, _ := cmd.Flags().GetBool("all")

	confluenceUrl, _ := cmd.Flags().GetString("confluence")

	// TODO move to confluence file NewPlugin
	if confluenceUrl != "" {
		confluenceUser, _ := cmd.Flags().GetString("confluence-user")
		// confluenceSpaces, _ := cmd.Flags().GetString("confluence-spaces")
		confluenceToken, _ := cmd.Flags().GetString("confluence-token")

		if !strings.HasPrefix("https://", confluenceUrl) && !strings.HasPrefix("http://", confluenceUrl) {
			confluenceUrl = fmt.Sprintf("https://%v", confluenceUrl)
		}
		confluenceUrl = strings.TrimRight(confluenceUrl, "/")
		plugins.AddPlugin("confluence", confluenceUrl, confluenceUser, confluenceToken)
	}

	contents, err := plugins.RunPlugins()
	if err != nil {
		log.Fatal().Msg(err.Error())
	}

	report := reporting.Report{}
	report.Results = make(map[string][]reporting.Secret)

	// Run with default configuration
	if allRules {
		wrap := wrapper.NewWrapper()

		for _, c := range contents {
			secrets := wrap.Detect(c.Content)
			report.Results[c.OriginalUrl] = append(report.Results[c.OriginalUrl], secrets...)
		}
		report.TotalItemsScanned = len(contents)
	}
	reporting.ShowReport(report)
}
