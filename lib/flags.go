package lib

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// BindFlags fill flags values with config file or environment variables data
func BindFlags(cmd *cobra.Command, v *viper.Viper, envPrefix string) error {
	log.Debug().Msg("console.bindFlags()")
	settingsMap := v.AllSettings()
	cmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		settingsMap[f.Name] = true
		if strings.Contains(f.Name, "-") {
			envVarSuffix := strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
			variableName := fmt.Sprintf("%s_%s", envPrefix, envVarSuffix)
			if err := v.BindEnv(f.Name, variableName); err != nil {
				log.Err(err).Msg("Failed to bind Viper flags")
			}
		}
		if !f.Changed && v.IsSet(f.Name) {
			val := v.Get(f.Name)
			setBoundFlags(f.Name, val, cmd)
		}
	})
	for key, val := range settingsMap {
		if val != true {
			return fmt.Errorf("unknown configuration key: '%s'\nShowing help for '%s' command", key, cmd.Name())
		}
	}
	return nil
}

func setBoundFlags(flagName string, val interface{}, cmd *cobra.Command) {
	switch t := val.(type) {
	case []interface{}:
		var paramSlice []string
		for _, param := range t {
			paramSlice = append(paramSlice, param.(string))
		}
		valStr := strings.Join(paramSlice, ",")
		if err := cmd.Flags().Set(flagName, valStr); err != nil {
			log.Err(err).Msg("Failed to set Viper flags")
		}
	default:
		newVal := fmt.Sprintf("%v", val)
		if err := cmd.PersistentFlags().Set(flagName, newVal); err != nil {
			log.Err(err).Msg("Failed to set Viper flags")
		}
	}
}
