package cmd

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/checkmarx/2ms/lib"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func initialize() {
	configFilePath, err := rootCmd.Flags().GetString(configFileFlag)
	if err != nil {
		cobra.CheckErr(err)
	}
	cobra.CheckErr(lib.LoadConfig(vConfig, configFilePath))
	cobra.CheckErr(lib.BindFlags(rootCmd, vConfig, envPrefix))

	logLevel := zerolog.InfoLevel
	switch strings.ToLower(logLevelVar) {
	case "trace":
		logLevel = zerolog.TraceLevel
	case "debug":
		logLevel = zerolog.DebugLevel
	case "info":
		logLevel = zerolog.InfoLevel
	case "warn":
		logLevel = zerolog.WarnLevel
	case "err", "error":
		logLevel = zerolog.ErrorLevel
	case "fatal":
		logLevel = zerolog.FatalLevel
	}
	zerolog.SetGlobalLevel(logLevel)
	log.Logger = log.Logger.Level(logLevel)
}

func validateFormat(stdout string, reportPath []string) error {
	r := regexp.MustCompile(outputFormatRegexpPattern)
	if !(r.MatchString(stdout)) {
		return fmt.Errorf(`invalid output format: %s, available formats are: json, yaml and sarif`, stdout)
	}

	for _, path := range reportPath {
		fileExtension := filepath.Ext(path)
		format := strings.TrimPrefix(fileExtension, ".")
		if !(r.MatchString(format)) {
			return fmt.Errorf(`invalid report extension: %s, available extensions are: json, yaml and sarif`, format)
		}
	}

	return nil
}
