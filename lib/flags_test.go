package lib_test

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/checkmarx/2ms/lib"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// TODO: positional arguments
// TODO: same flag name in different commands level
// TODO: assert.Equal to the expected value and not to viper value because I don't care about the viper key and value.
// TODO: replace expected with actual

const envVarPrefix = "PREFIX"

func TestBindFlags(t *testing.T) {
	t.Run("BindFlags_TestEmptyViper", func(t *testing.T) {
		assertClearEnv(t)
		defer clearEnvVars(t)

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
		assertClearEnv(t)
		defer clearEnvVars(t)

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
		assertClearEnv(t)
		defer clearEnvVars(t)

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
		assertClearEnv(t)
		defer clearEnvVars(t)

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
		assertClearEnv(t)
		defer clearEnvVars(t)

		arr := []string{"test", "array", "flag"}

		cmd := &cobra.Command{}
		v := getViper()

		var (
			// testArraySpaces []string
			testArrayCommas []string
		)

		// cmd.PersistentFlags().StringSliceVar(&testArraySpaces, "test-array-spaces", []string{}, "Test array flag")
		cmd.PersistentFlags().StringSliceVar(&testArrayCommas, "test-array-commas", []string{}, "Test array flag")

		// err := setEnv("PREFIX_TEST_ARRAY_SPACES", strings.Join(arr, " "))
		// assert.NoError(t, err)
		err := setEnv("PREFIX_TEST_ARRAY_COMMAS", strings.Join(arr, ","))
		assert.NoError(t, err)

		err = lib.BindFlags(cmd, v, envVarPrefix)
		assert.NoError(t, err)

		// assert.NotEmpty(t, v.GetStringSlice("test-array-spaces"))
		assert.NotEmpty(t, v.GetStringSlice("test-array-commas"))

		// assert.Equal(t, testArraySpaces, arr)
		assert.Equal(t, testArrayCommas, arr)
	})

	t.Run("BindFlags_ReturnsErrorForUnknownConfigurationKeys", func(t *testing.T) {
		t.Skip("Not sure if we need this feature.")
		assertClearEnv(t)
		defer clearEnvVars(t)

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
		assertClearEnv(t)
		defer clearEnvVars(t)

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
		assertClearEnv(t)
		defer clearEnvVars(t)

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

	t.Run("BindFlags_SameFlagNameDifferentCmd_Root", func(t *testing.T) {
		/*
			When the same flag name is used in different commands, the last command
			will overwrite the previous one.
			var (
				cmd1op1 string
				cmd1op2 string
				rootOp1 string
				rootOp2 string
			)

			func Execute() {
				var rootCmd = &cobra.Command{
					Use: "",
					Run: func(cmd *cobra.Command, args []string) {
						log.Printf("cmd1op1: %s", cmd1op1)
						log.Printf("cmd1op2: %s", cmd1op2)
						log.Printf("rootOp1: %s", rootOp1)
						log.Printf("rootOp2: %s", rootOp2)
					},
				}

				cmd1 := &cobra.Command{
					Use: "cmd1",
					Run: func(cmd *cobra.Command, args []string) {
						log.Printf("cmd1op1: %s", cmd1op1)
						log.Printf("cmd1op2: %s", cmd1op2)
						log.Printf("rootOp1: %s", rootOp1)
						log.Printf("rootOp2: %s", rootOp2)
					},
				}
				cmd1.PersistentFlags().StringVar(&cmd1op1, "op1", "", "persistent option1 for cmd1, not required for rootCmd")
				cmd1.Flags().StringVar(&cmd1op2, "op2", "", "option2 for cmd1, not required for rootCmd")
				rootCmd.AddCommand(cmd1)

				rootCmd.PersistentFlags().StringVar(&rootOp1, "op1", "", "persistent option1 for rootCmd, not required for cmd1")
				rootCmd.Flags().StringVar(&rootOp2, "op2", "", "option2 for rootCmd, not required for cmd1")

				err := rootCmd.Execute()
				if err != nil {
					os.Exit(1)
				}
			}
		*/
		assertClearEnv(t)
		defer clearEnvVars(t)

		rootCmd := &cobra.Command{}
		cmd1 := &cobra.Command{}
		cmd2 := &cobra.Command{}
		v := getViper()

		var (
			testStringRoot           string
			testStringPersistentRoot string
			testString1              string
			testStringPersistent1    string
			testString2              string
			testStringPersistent2    string
		)

		rootCmd.Flags().StringVar(&testStringRoot, "test-string", "", "Test string flag")
		rootCmd.PersistentFlags().StringVar(&testStringPersistentRoot, "test-string-persistent", "", "Test string flag")
		cmd1.Flags().StringVar(&testString1, "test-string", "", "Test string flag")
		cmd1.PersistentFlags().StringVar(&testStringPersistent1, "test-string-persistent", "", "Test string flag")
		cmd2.Flags().StringVar(&testString2, "test-string", "", "Test string flag")
		cmd2.PersistentFlags().StringVar(&testStringPersistent2, "test-string-persistent", "", "Test string flag")

		rootCmd.AddCommand(cmd1)
		rootCmd.AddCommand(cmd2)

		err := setEnv("prefix_test_string", "test-string-value")
		assert.NoError(t, err)
		err = setEnv("prefix_test_string_persistent", "test-string-persistent-value")
		assert.NoError(t, err)

		err = lib.BindFlags(rootCmd, v, envVarPrefix)
		assert.NoError(t, err)

		assert.Equal(t, "test-string-value", testStringRoot)
		assert.Equal(t, "test-string-persistent-value", testStringPersistentRoot)
		assert.Empty(t, testString1)
		assert.Empty(t, testStringPersistent1)
		assert.Empty(t, testString2)
		assert.Empty(t, testStringPersistent2)
	})

	t.Run("BindFlags_FromYAML_RootCMD", func(t *testing.T) {
		assertClearEnv(t)
		defer clearEnvVars(t)

		yamlConfig := []byte(`
test-string: test-string-value
test-int: 123
test-bool: true
test-array:
  - test
  - array
  - flag
test-float: 123.456
`)

		cmd := &cobra.Command{}
		v := getViper()
		v.SetConfigType("yaml")
		v.ReadConfig(bytes.NewBuffer(yamlConfig))

		var (
			testString string
			testInt    int
			testBool   bool
			testArray  []string
			testFloat  float64
		)

		cmd.PersistentFlags().StringVar(&testString, "test-string", "", "Test string flag")
		cmd.Flags().IntVar(&testInt, "test-int", 0, "Test int flag")
		cmd.PersistentFlags().BoolVar(&testBool, "test-bool", false, "Test bool flag")
		cmd.Flags().StringSliceVar(&testArray, "test-array", []string{}, "Test array flag")
		cmd.PersistentFlags().Float64Var(&testFloat, "test-float", 0, "Test float flag")

		err := lib.BindFlags(cmd, v, envVarPrefix)
		assert.NoError(t, err)

		assert.NotEmpty(t, v.GetString("test-string"))
		assert.NotEmpty(t, v.GetInt("test-int"))
		assert.NotEmpty(t, v.GetBool("test-bool"))
		assert.NotEmpty(t, v.GetStringSlice("test-array"))
		assert.NotEmpty(t, v.GetFloat64("test-float"))

		assert.Equal(t, testString, v.GetString("test-string"))
		assert.Equal(t, testInt, v.GetInt("test-int"))
		assert.Equal(t, testBool, v.GetBool("test-bool"))
		assert.Equal(t, testArray, v.GetStringSlice("test-array"))
		assert.Equal(t, testFloat, v.GetFloat64("test-float"))
	})

	t.Run("BindFlags_FromYAML_SubCMD", func(t *testing.T) {
		assertClearEnv(t)
		defer clearEnvVars(t)

		yamlConfig := []byte(`
global-string: global-string-value
subCommand:
  test-string: test-string-value
  test-int: 123
  test-bool: true
`)

		cmd := &cobra.Command{}
		v := getViper()
		v.SetConfigType("yaml")
		v.ReadConfig(bytes.NewBuffer(yamlConfig))

		var (
			globalString string
			testString   string
			testInt      int
			testBool     bool
		)

		cmd.PersistentFlags().StringVar(&globalString, "global-string", "", "Global string flag")
		subCmd := &cobra.Command{
			Use: "subCommand",
		}
		cmd.AddCommand(subCmd)
		subCmd.PersistentFlags().StringVar(&testString, "test-string", "", "Test string flag")
		subCmd.Flags().IntVar(&testInt, "test-int", 0, "Test int flag")
		subCmd.PersistentFlags().BoolVar(&testBool, "test-bool", false, "Test bool flag")

		err := lib.BindFlags(cmd, v, envVarPrefix)
		assert.NoError(t, err)

		assert.NotEmpty(t, v.GetString("global-string"))
		assert.NotEmpty(t, v.GetString("subCommand.test-string"))
		assert.NotEmpty(t, v.GetInt("subCommand.test-int"))
		assert.NotEmpty(t, v.GetBool("subCommand.test-bool"))

		assert.Equal(t, globalString, v.GetString("global-string"))
		assert.Equal(t, testString, v.GetString("subCommand.test-string"))
		assert.Equal(t, testInt, v.GetInt("subCommand.test-int"))
		assert.Equal(t, testBool, v.GetBool("subCommand.test-bool"))
	})

	t.Run("BindFlags_FromYAML_SubCMD_WithEnvVars", func(t *testing.T) {
		assertClearEnv(t)
		defer clearEnvVars(t)

		yamlConfig := []byte(`
global-string: global-string-value
subCommand:
  test-string: test-string-value
  test-int: 123
  test-bool: true
`)
		cmd := &cobra.Command{}
		v := getViper()
		v.SetConfigType("yaml")
		v.ReadConfig(bytes.NewBuffer(yamlConfig))

		var (
			globalString string
			testString   string
			testInt      int
			testBool     bool
		)

		cmd.PersistentFlags().StringVar(&globalString, "global-string", "", "Global string flag")
		subCmd := &cobra.Command{
			Use: "subCommand",
		}
		cmd.AddCommand(subCmd)
		subCmd.PersistentFlags().StringVar(&testString, "test-string", "", "Test string flag")
		subCmd.Flags().IntVar(&testInt, "test-int", 0, "Test int flag")
		subCmd.PersistentFlags().BoolVar(&testBool, "test-bool", false, "Test bool flag")

		err := setEnv("PREFIX_GLOBAL_STRING", "global-string-value-from-env")
		assert.NoError(t, err)
		err = setEnv("PREFIX_TEST_STRING", "test-string-value-from-env")
		assert.NoError(t, err)

		err = lib.BindFlags(cmd, v, envVarPrefix)
		assert.NoError(t, err)

		assert.Equal(t, globalString, "global-string-value-from-env")
		assert.Equal(t, testString, "test-string-value-from-env")
		assert.Equal(t, testInt, 123)
		assert.Equal(t, testBool, true)
	})

	t.Run("BindFlags_FromYAML_SubSubCmd", func(t *testing.T) {
		assertClearEnv(t)
		defer clearEnvVars(t)

		yamlConfig := []byte(`
global-string: global-string-value
subCommand:
  first-string: string-from-sub-command
  subSubCommand:
    second-string: string from sub-sub command
`)
		cmd := &cobra.Command{}
		v := getViper()
		v.SetConfigType("yaml")
		v.ReadConfig(bytes.NewBuffer(yamlConfig))

		var (
			globalString string
			firstString  string
			secondString string
		)

		subSubCmd := &cobra.Command{
			Use: "subSubCommand",
		}
		subCmd := &cobra.Command{
			Use: "subCommand",
		}
		subCmd.AddCommand(subSubCmd)
		cmd.AddCommand(subCmd)
		cmd.PersistentFlags().StringVar(&globalString, "global-string", "", "Global string flag")
		subCmd.PersistentFlags().StringVar(&firstString, "first-string", "", "Test string flag")
		subSubCmd.Flags().StringVar(&secondString, "second-string", "", "Test string flag")

		err := lib.BindFlags(cmd, v, envVarPrefix)
		assert.NoError(t, err)

		assert.Equal(t, "global-string-value", globalString)
		assert.Equal(t, "string-from-sub-command", firstString)
		assert.Equal(t, "string from sub-sub command", secondString)
	})

	t.Run("BindFlags_FromYAML_SameFlagName_Root", func(t *testing.T) {
		assertClearEnv(t)
		defer clearEnvVars(t)

		yamlConfig := []byte(`
test-string: global-string-value
subCommand:
  dummy-string: string-from-sub-command
`)

		cmd := &cobra.Command{}
		v := getViper()
		v.SetConfigType("yaml")
		v.ReadConfig(bytes.NewBuffer(yamlConfig))

		var (
			testStringRoot string
			testStringSub  string
		)

		subCmd := &cobra.Command{
			Use: "subCommand",
		}
		cmd.AddCommand(subCmd)

		cmd.PersistentFlags().StringVar(&testStringRoot, "test-string", "", "Test string flag")
		subCmd.PersistentFlags().StringVar(&testStringSub, "test-string", "", "Test string flag")

		err := lib.BindFlags(cmd, v, envVarPrefix)
		assert.NoError(t, err)

		assert.Equal(t, "global-string-value", testStringRoot)
		assert.Equal(t, "", testStringSub)
	})

	t.Run("BindFlags_FromYAML_SameFlagName_SubCmd", func(t *testing.T) {
		assertClearEnv(t)
		defer clearEnvVars(t)

		yamlConfig := []byte(`
test-string: global-string-value
subCommand:
  test-string: string-from-sub-command
`)

		cmd := &cobra.Command{}
		v := getViper()
		v.SetConfigType("yaml")
		v.ReadConfig(bytes.NewBuffer(yamlConfig))

		var (
			testStringRoot string
			testStringSub  string
		)

		subCmd := &cobra.Command{
			Use: "subCommand",
		}

		cmd.PersistentFlags().StringVar(&testStringRoot, "test-string", "", "Test string flag")
		subCmd.PersistentFlags().StringVar(&testStringSub, "test-string", "", "Test string flag")

		cmd.AddCommand(subCmd)

		err := lib.BindFlags(cmd, v, envVarPrefix)
		assert.NoError(t, err)

		assert.Equal(t, "", testStringRoot)
		assert.Equal(t, "string-from-sub-command", testStringSub)
	})
}

var envKeys []string

func assertClearEnv(t *testing.T) {
	assert.Len(t, envKeys, 0)
}

func setEnv(key, value string) error {
	envKeys = append(envKeys, key)
	return os.Setenv(key, value)
}

func clearEnvVars(t *testing.T) {
	for len(envKeys) > 0 {
		key := envKeys[0]
		err := os.Unsetenv(key)
		assert.NoError(t, err)
		envKeys = envKeys[1:]
	}
}

func getViper() *viper.Viper {
	v := viper.New()
	v.SetEnvPrefix(envVarPrefix)

	return v
}
