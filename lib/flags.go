package lib

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// TODO: remove cmd dependency
func LoadConfigFromAllSources(rootCmd *cobra.Command, config *viper.Viper, configFileFlagName string, envPrefix string) error {
	configFilePath, err := rootCmd.Flags().GetString(configFileFlagName)
	if err != nil {
		return err
	}

	if configFilePath != "" {
		// TODO: Yaml? JSON?
		config.SetConfigFile(configFilePath)
		if err := config.ReadInConfig(); err != nil {
			return err
		}
	}

	return nil
}

// TODO: can be a package
// TODO: can be private now?
// BindFlags fill flags values with config file or environment variables data
func BindFlags(cmd *cobra.Command, v *viper.Viper, envPrefix string) error {
	commandHierarchy := getCommandHierarchy(cmd)

	bindFlag := func(f *pflag.Flag) {
		fullFlagName := fmt.Sprintf("%s%s", commandHierarchy, f.Name)
		bindEnvVarIntoViper(v, fullFlagName, envPrefix)

		if f.Changed {
			return
		}

		if v.IsSet(fullFlagName) {
			val := v.Get(fullFlagName)
			applyViperFlagToCommand(f, val, cmd)
		}
	}
	// TODO: remove persistent flags
	cmd.PersistentFlags().VisitAll(bindFlag)
	cmd.Flags().VisitAll(bindFlag)

	for _, subCmd := range cmd.Commands() {
		if err := BindFlags(subCmd, v, envPrefix); err != nil {
			return err
		}
	}

	return nil
}

func bindEnvVarIntoViper(v *viper.Viper, fullFlagName, envPrefix string) {
	envVarSuffix := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(fullFlagName, "-", "_"), ".", "_"))
	envVarName := fmt.Sprintf("%s_%s", envPrefix, envVarSuffix)

	if err := v.BindEnv(fullFlagName, envVarName, strings.ToLower(envVarName)); err != nil {
		log.Err(err).Msg("Failed to bind Viper flags")
	}
}

func applyViperFlagToCommand(flag *pflag.Flag, val interface{}, cmd *cobra.Command) {
	switch t := val.(type) {
	case []interface{}:
		var paramSlice []string
		for _, param := range t {
			paramSlice = append(paramSlice, param.(string))
		}
		valStr := strings.Join(paramSlice, ",")
		if err := flag.Value.Set(valStr); err != nil {
			log.Err(err).Msg("Failed to set Viper flags")
		}
	default:
		newVal := fmt.Sprintf("%v", val)
		if err := flag.Value.Set(newVal); err != nil {
			log.Err(err).Msg("Failed to set Viper flags")
		}
	}
	flag.Changed = true
}

func getCommandHierarchy(cmd *cobra.Command) string {
	names := []string{}
	if !cmd.HasParent() {
		return ""
	}

	for parent := cmd; parent.HasParent() && parent.Name() != ""; parent = parent.Parent() {
		names = append([]string{parent.Name()}, names...)
	}

	if len(names) == 0 {
		return ""
	}

	return strings.Join(names, ".") + "."
}
