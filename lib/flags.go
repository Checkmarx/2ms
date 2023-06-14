package lib

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// TODO: can be a package
// BindFlags fill flags values with config file or environment variables data
func BindFlags(cmd *cobra.Command, v *viper.Viper, envPrefix string) error {

	bindFlag := func(f *pflag.Flag) {
		bindEnvVarIntoViper(f, v, envPrefix)

		if f.Changed {
			return
		}

		hirarchy := fmt.Sprintf("%s.%s", cmd.Name(), f.Name)
		if v.IsSet(hirarchy) {
			val := v.Get(hirarchy)
			applyViperFlagToCommand(f, val, cmd)
		}

		if v.IsSet(f.Name) {
			val := v.Get(f.Name)
			applyViperFlagToCommand(f, val, cmd)
		}
	}

	cmd.PersistentFlags().VisitAll(bindFlag)
	cmd.Flags().VisitAll(bindFlag)

	for _, subCmd := range cmd.Commands() {
		if err := BindFlags(subCmd, v, envPrefix); err != nil {
			return err
		}
	}

	return nil
}

func bindEnvVarIntoViper(f *pflag.Flag, v *viper.Viper, envPrefix string) {
	envVarSuffix := strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
	envVarName := fmt.Sprintf("%s_%s", envPrefix, envVarSuffix)

	if err := v.BindEnv(f.Name, envVarName, strings.ToLower(envVarName)); err != nil {
		log.Err(err).Msg("Failed to bind Viper flags")
	}
}

func applyViperFlagToCommand(flag *pflag.Flag, val interface{}, cmd *cobra.Command) {
	switch t := val.(type) {
	// TODO: remove this case?
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
}
