package lib_test

import (
	"os"
	"testing"

	"github.com/checkmarx/2ms/lib"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// TODO: positional arguments
// TODO: other resources

const envVarPrefix = "PREFIX"

func TestBindFlags(t *testing.T) {
	t.Run("BindFlags_TestEmptyViper", func(t *testing.T) {
		cmd := &cobra.Command{}
		v := getViper()

		var (
			testString  string
			testInt     int
			testBool    bool
			testFloat64 float64
		)

		cmd.PersistentFlags().StringVar(&testString, "test-string", "", "Test string flag")
		cmd.PersistentFlags().IntVar(&testInt, "test-int", 0, "Test int flag")
		cmd.PersistentFlags().BoolVar(&testBool, "test-bool", false, "Test bool flag")
		cmd.PersistentFlags().Float64Var(&testFloat64, "test-float64", 0.0, "Test float64 flag")

		err := lib.BindFlags(cmd, v, envVarPrefix)
		assert.NoError(t, err)

		assert.Equal(t, testString, v.GetString("test-string"))
		assert.Equal(t, testInt, v.GetInt("test-int"))
		assert.Equal(t, testBool, v.GetBool("test-bool"))
		assert.Equal(t, testFloat64, v.GetFloat64("test-float64"))
	})

	t.Run("BindFlags_FromEnvVarsToCobraCommand", func(t *testing.T) {
		cmd := &cobra.Command{}
		v := getViper()
		v.SetEnvPrefix(envVarPrefix)

		var (
			testString  string
			testInt     int
			testBool    bool
			testFloat64 float64
		)

		cmd.PersistentFlags().StringVar(&testString, "test-string", "", "Test string flag")
		cmd.PersistentFlags().IntVar(&testInt, "test-int", 0, "Test int flag")
		cmd.PersistentFlags().BoolVar(&testBool, "test-bool", false, "Test bool flag")
		cmd.PersistentFlags().Float64Var(&testFloat64, "test-float64", 0.0, "Test float64 flag")

		err := setEnv("PREFIX_TEST_STRING", "test-string-value")
		assert.NoError(t, err)
		err = setEnv("PREFIX_TEST_INT", "456")
		assert.NoError(t, err)
		err = setEnv("PREFIX_TEST_BOOL", "true")
		assert.NoError(t, err)
		err = setEnv("PREFIX_TEST_FLOAT64", "1.23")
		assert.NoError(t, err)

		err = lib.BindFlags(cmd, v, envVarPrefix)
		assert.NoError(t, err)

		assert.NotEmpty(t, v.GetString("test-string"))
		assert.NotEmpty(t, v.GetInt("test-int"))
		assert.NotEmpty(t, v.GetBool("test-bool"))
		assert.NotEmpty(t, v.GetFloat64("test-float64"))

		assert.Equal(t, testString, v.GetString("test-string"))
		assert.Equal(t, testInt, v.GetInt("test-int"))
		assert.Equal(t, testBool, v.GetBool("test-bool"))
		assert.Equal(t, testFloat64, v.GetFloat64("test-float64"))

	})

	t.Run("BindFlags_NonPersistentFlags", func(t *testing.T) {
		cmd := &cobra.Command{}
		v := getViper()

		var (
			testString string
		)

		cmd.Flags().StringVar(&testString, "test-string", "", "Test string flag")

		err := setEnv("PREFIX_TEST_STRING", "test-string-value")
		assert.NoError(t, err)

		err = lib.BindFlags(cmd, v, envVarPrefix)
		assert.NoError(t, err)

		assert.NotEmpty(t, v.GetString("test-string"))
		assert.Equal(t, testString, v.GetString("test-string"))
	})

	t.Run("BindFlags_Subcommand", func(t *testing.T) {
		var (
			testString string
			testInt    int
		)

		subCommand := &cobra.Command{}
		subCommand.Flags().StringVar(&testString, "test-string", "", "Test string flag")
		subCommand.PersistentFlags().IntVar(&testInt, "test-int", 0, "Test int flag")

		cmd := &cobra.Command{}
		cmd.AddCommand(subCommand)
		v := getViper()

		err := setEnv("PREFIX_TEST_STRING", "test-string-value")
		assert.NoError(t, err)
		err = setEnv("PREFIX_TEST_INT", "456")
		assert.NoError(t, err)

		err = lib.BindFlags(cmd, v, envVarPrefix)
		assert.NoError(t, err)

		assert.NotEmpty(t, v.GetString("test-string"))
		assert.NotEmpty(t, v.GetInt("test-int"))

		assert.Equal(t, testString, v.GetString("test-string"))
		assert.Equal(t, testInt, v.GetInt("test-int"))
	})

	t.Run("BindFlags_ArrayFlag", func(t *testing.T) {
		cmd := &cobra.Command{}
		v := getViper()

		var (
			testArray []string
		)

		cmd.PersistentFlags().StringSliceVar(&testArray, "test-array", []string{}, "Test array flag")

		err := setEnv("PREFIX_TEST_ARRAY", "test,array,value")
		assert.NoError(t, err)

		err = lib.BindFlags(cmd, v, envVarPrefix)
		assert.NoError(t, err)

		assert.NotEmpty(t, v.GetStringSlice("test-array"))
		assert.Equal(t, testArray, v.GetStringSlice("test-array"))
	})

	t.Run("BindFlags_ReturnsErrorForUnknownConfigurationKeys", func(t *testing.T) {
		cmd := &cobra.Command{}
		v := getViper()

		var (
			testString string
		)

		cmd.PersistentFlags().StringVar(&testString, "test-string", "", "Test string flag")

		v.Set("unknown-key", "unknown-value")

		err := lib.BindFlags(cmd, v, envVarPrefix)

		assert.EqualError(t, err, "unknown configuration key: 'unknown-key'\nShowing help for '' command")
	})

	t.Run("BindFlags_LowerCaseEnvVars", func(t *testing.T) {
		cmd := &cobra.Command{}
		v := getViper()

		var (
			testString string
		)

		cmd.PersistentFlags().StringVar(&testString, "test-string", "", "Test string flag")

		err := setEnv("prefix_test_string", "test-string-value")
		assert.NoError(t, err)

		err = lib.BindFlags(cmd, v, envVarPrefix)
		assert.NoError(t, err)

		assert.NotEmpty(t, v.GetString("test-string"))
		assert.Equal(t, testString, v.GetString("test-string"))
	})

	t.Run("BindFlags_OneWordFlagName", func(t *testing.T) {
		cmd := &cobra.Command{}
		v := getViper()

		var (
			testString string
		)

		cmd.Flags().StringVar(&testString, "teststring", "", "Test string flag")

		err := setEnv("prefix_teststring", "test-string-value")
		assert.NoError(t, err)

		err = lib.BindFlags(cmd, v, envVarPrefix)
		assert.NoError(t, err)

		assert.NotEmpty(t, v.GetString("teststring"))
		assert.Equal(t, testString, v.GetString("teststring"))
	})
}

// TODO: dont change the env vars!
// Helper function to set an environment variable for testing
func setEnv(key, value string) error {
	return os.Setenv(key, value)
}

func getViper() *viper.Viper {
	v := viper.New()
	v.SetEnvPrefix(envVarPrefix)

	return v
}
