package lib_test

import (
	"os"
	"testing"

	"github.com/checkmarx/2ms/lib"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// TODO: test subcommand
// TODO: test array
// TODO: test persistent and not persistent flags
// TODO: lowercase and uppercase env vars
// TODO: test unknown configuration flag (flag in viper but not in cobra)
// TODO: positional arguments

func TestBindFlags(t *testing.T) {
	t.Run("BindFlags_TestEmptyViper", func(t *testing.T) {
		cmd := &cobra.Command{}
		v := viper.New()

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

		err := lib.BindFlags(cmd, v, "PREFIX")
		assert.NoError(t, err)

		assert.Equal(t, testString, v.GetString("test-string"))
		assert.Equal(t, testInt, v.GetInt("test-int"))
		assert.Equal(t, testBool, v.GetBool("test-bool"))
		assert.Equal(t, testFloat64, v.GetFloat64("test-float64"))
	})

	t.Run("BindFlags_FromEnvVarsToCobraCommand", func(t *testing.T) {
		cmd := &cobra.Command{}
		v := viper.New()
		v.SetEnvPrefix("PREFIX")

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

		err = lib.BindFlags(cmd, v, "PREFIX")
		assert.NoError(t, err)

		assert.Equal(t, testString, v.GetString("test-string"))
		assert.Equal(t, testInt, v.GetInt("test-int"))
		assert.Equal(t, testBool, v.GetBool("test-bool"))
		assert.Equal(t, testFloat64, v.GetFloat64("test-float64"))

	})

	t.Run("BindFlags_NonPersistentFlags", func(t *testing.T) {

		cmd := &cobra.Command{}
		v := viper.New()

		var (
			testString string
		)

		cmd.Flags().StringVar(&testString, "test-string", "", "Test string flag")

		err := setEnv("PREFIX_TEST_STRING", "test-string-value")
		assert.NoError(t, err)

		err = lib.BindFlags(cmd, v, "PREFIX")
		assert.NoError(t, err)

		assert.Equal(t, testString, v.GetString("test-string"))
	})

	t.Run("BindFlags_ReturnsErrorForUnknownConfigurationKeys", func(t *testing.T) {
		// Create a new Cobra command and Viper instance
		cmd := &cobra.Command{}
		v := viper.New()

		// Define some test flags
		var (
			testString string
		)

		// Add the test flag to the command
		cmd.PersistentFlags().StringVar(&testString, "test-string", "", "Test string flag")

		// Set an unknown configuration key
		v.Set("unknown-key", "unknown-value")

		// Bind the flags to the Viper instance
		err := lib.BindFlags(cmd, v, "PREFIX")

		// Test that an error is returned for unknown configuration keys
		assert.EqualError(t, err, "unknown configuration key: 'unknown-key'\nShowing help for '' command")
	})
}

// Helper function to set an environment variable for testing
func setEnv(key, value string) error {
	return os.Setenv(key, value)
}
