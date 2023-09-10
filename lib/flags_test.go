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

		assert.Empty(t, testString)
		assert.Empty(t, testInt)
		assert.Empty(t, testBool)
		assert.Empty(t, testFloat64)
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

		assert.Equal(t, "test-string-value", testString)
		assert.Equal(t, 456, testInt)
		assert.Equal(t, true, testBool)
		assert.Equal(t, 1.23, testFloat64)
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

		assert.Equal(t, "test-string-value", testString)
	})

	t.Run("BindFlags_Subcommand", func(t *testing.T) {
		assertClearEnv(t)
		defer clearEnvVars(t)

		var (
			testString string
			testInt    int
		)

		subCommand := &cobra.Command{
			Use: "subCommand",
		}
		subCommand.Flags().StringVar(&testString, "test-string", "", "Test string flag")
		subCommand.PersistentFlags().IntVar(&testInt, "test-int", 0, "Test int flag")

		cmd := &cobra.Command{}
		cmd.AddCommand(subCommand)
		v := getViper()

		err := setEnv("PREFIX_SUBCOMMAND_TEST_STRING", "test-string-value")
		assert.NoError(t, err)
		err = setEnv("PREFIX_SUBCOMMAND_TEST_INT", "456")
		assert.NoError(t, err)

		err = lib.BindFlags(cmd, v, envVarPrefix)
		assert.NoError(t, err)

		assert.Equal(t, "test-string-value", testString)
		assert.Equal(t, 456, testInt)
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

		// assert.Equal(t, testArraySpaces, arr)
		assert.Equal(t, arr, testArrayCommas)
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

		assert.Equal(t, "test-string-value", testString)
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

		assert.Equal(t, "test-string-value", testString)
	})

	t.Run("BindFlags_SameFlagNameDifferentCmd", func(t *testing.T) {

		assertClearEnv(t)
		defer clearEnvVars(t)

		rootCmd := &cobra.Command{
			Use: "root",
		}
		cmd1 := &cobra.Command{
			Use: "cmd1",
		}
		cmd2 := &cobra.Command{
			Use: "cmd2",
		}
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
		err = setEnv("prefix_cmd1_test_string", "test-string-value-cmd1")
		assert.NoError(t, err)
		err = setEnv("prefix_cmd1_test_string_persistent", "test-string-persistent-value-cmd1")
		assert.NoError(t, err)
		err = setEnv("prefix_cmd2_test_string", "test-string-value-cmd2")
		assert.NoError(t, err)
		err = setEnv("prefix_cmd2_test_string_persistent", "test-string-persistent-value-cmd2")
		assert.NoError(t, err)

		err = lib.BindFlags(rootCmd, v, envVarPrefix)
		assert.NoError(t, err)

		assert.Equal(t, "test-string-value", testStringRoot)
		assert.Equal(t, "test-string-persistent-value", testStringPersistentRoot)
		assert.Equal(t, "test-string-value-cmd1", testString1)
		assert.Equal(t, "test-string-persistent-value-cmd1", testStringPersistent1)
		assert.Equal(t, "test-string-value-cmd2", testString2)
		assert.Equal(t, "test-string-persistent-value-cmd2", testStringPersistent2)
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
		assert.NoError(t, v.ReadConfig(bytes.NewBuffer(yamlConfig)))

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

		assert.Equal(t, "test-string-value", testString)
		assert.Equal(t, 123, testInt)
		assert.Equal(t, true, testBool)
		assert.Equal(t, []string{"test", "array", "flag"}, testArray)
		assert.Equal(t, 123.456, testFloat)
	})

	t.Run("BindFlags_FromYAML_StringArrayVar", func(t *testing.T) {
		assertClearEnv(t)
		defer clearEnvVars(t)

		yamlConfig := []byte(`
regex:
  - test\=
  - array\=
  - flag\=
another-regex: [test\=, array\=, flag\=]
`)

		cmd := &cobra.Command{}
		v := getViper()
		v.SetConfigType("yaml")
		assert.NoError(t, v.ReadConfig(bytes.NewBuffer(yamlConfig)))

		var testArray []string
		cmd.Flags().StringArrayVar(&testArray, "regex", []string{}, "Test array flag")
		cmd.Flags().StringArrayVar(&testArray, "another-regex", []string{}, "Test array flag")

		err := lib.BindFlags(cmd, v, envVarPrefix)
		assert.NoError(t, err)

		assert.Equal(t, []string{"test\\=", "array\\=", "flag\\="}, testArray)
		assert.Equal(t, []string{"test\\=", "array\\=", "flag\\="}, testArray)
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
		assert.NoError(t, v.ReadConfig(bytes.NewBuffer(yamlConfig)))

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

		assert.Equal(t, "global-string-value", globalString)
		assert.Equal(t, "test-string-value", testString)
		assert.Equal(t, 123, testInt)
		assert.Equal(t, true, testBool)
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
		assert.NoError(t, v.ReadConfig(bytes.NewBuffer(yamlConfig)))

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
		err = setEnv("PREFIX_SUBCOMMAND_TEST_STRING", "test-string-value-from-env")
		assert.NoError(t, err)

		err = lib.BindFlags(cmd, v, envVarPrefix)
		assert.NoError(t, err)

		assert.Equal(t, "global-string-value-from-env", globalString)
		assert.Equal(t, "test-string-value-from-env", testString)
		assert.Equal(t, 123, testInt)
		assert.Equal(t, true, testBool)
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
		assert.NoError(t, v.ReadConfig(bytes.NewBuffer(yamlConfig)))

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
		assert.NoError(t, v.ReadConfig(bytes.NewBuffer(yamlConfig)))

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
		assert.NoError(t, v.ReadConfig(bytes.NewBuffer(yamlConfig)))

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

		assert.Equal(t, "global-string-value", testStringRoot)
		assert.Equal(t, "string-from-sub-command", testStringSub)
	})

	t.Run("BindFlags_FromJSON", func(t *testing.T) {
		assertClearEnv(t)
		defer clearEnvVars(t)

		jsonConfig := []byte(`
			{
			  "global-string": "global-string-value",
			  "subCommand": {
				"test-string": "string-from-sub-command"
			  }
			}`)

		cmd := &cobra.Command{}
		v := getViper()
		v.SetConfigType("json")
		assert.NoError(t, v.ReadConfig(bytes.NewBuffer(jsonConfig)))

		subCmd := &cobra.Command{
			Use: "subCommand",
		}
		cmd.AddCommand(subCmd)

		globalString := cmd.PersistentFlags().String("global-string", "", "Global string flag")
		testString := subCmd.PersistentFlags().String("test-string", "", "Test string flag")

		err := lib.BindFlags(cmd, v, envVarPrefix)
		assert.NoError(t, err)

		assert.Equal(t, "global-string-value", *globalString)
		assert.Equal(t, "string-from-sub-command", *testString)
	})
}

func TestEndToEndWithExecute(t *testing.T) {
	configFlagName := "config"

	testCases := []struct {
		name         string
		args         []string
		envVars      map[string]string
		config       []byte
		configFormat string
	}{
		{
			name:    "from env vars",
			args:    []string{"subcommand"},
			envVars: map[string]string{"TEST_STRING": "env-value", "TEST_INT": "123", "SUBCOMMAND_TEST_BOOL": "true"},
		},
		{
			name: "from argument",
			args: []string{"subcommand", "--test-string", "argument-value", "--test-int", "123", "--test-bool", "true"},
		},
		{
			name: "from config",
			args: []string{"subcommand"},
			config: []byte(`
test-string: config-value
test-int: 123
subcommand:
  test-bool: true
`),
			configFormat: "yaml",
		},
		{
			name: "from argument and env vars",
			args: []string{"subcommand", "--test-string", "argument-value"},
			envVars: map[string]string{
				"TEST_INT":             "123",
				"SUBCOMMAND_TEST_BOOL": "true",
			},
		},
		{
			name: "from env vars and config",
			args: []string{"subcommand"},
			envVars: map[string]string{
				"TEST_STRING": "env-value",
			},
			config: []byte(`
test-int: 123
subcommand:
  test-bool: true
`),
			configFormat: "yaml",
		},
		{
			name: "from JSON config",
			args: []string{"subcommand"},
			config: []byte(`
				{
					"test-string": "config-value",
					"test-int": 123,
					"subcommand": {
						"test-bool": true
					}
				}`),
			configFormat: "json",
		},
	}

	var cmd *cobra.Command
	var v *viper.Viper

	cobra.OnInitialize(func() {
		configFilePath, err := cmd.Flags().GetString(configFlagName)
		if err != nil {
			cobra.CheckErr(err)
		}
		err = lib.LoadConfig(v, configFilePath)
		assert.NoError(t, err)
		err = lib.BindFlags(cmd, v, envVarPrefix)
		assert.NoError(t, err)
	})

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assertClearEnv(t)
			for key, value := range tc.envVars {
				err := setEnv(envVarPrefix+"_"+key, value)
				assert.NoError(t, err)
			}
			defer clearEnvVars(t)

			var configFileName string
			if tc.config != nil {
				configFileName = writeTempFile(t, tc.config, tc.configFormat)
				defer os.Remove(configFileName)

				tc.args = append(tc.args, "--"+configFlagName, configFileName)
			}

			cmd = &cobra.Command{
				Use: "root",
			}
			testString := cmd.PersistentFlags().String("test-string", "", "Test string flag")
			testInt := cmd.PersistentFlags().Int("test-int", 0, "Test int flag")
			assert.NoError(t, cmd.MarkPersistentFlagRequired("test-string"))
			cmd.PersistentFlags().String(configFlagName, "", "Config file name")

			var subcommandBool bool
			var subCommandExecuted bool
			subCmd := &cobra.Command{
				Use: "subcommand",
				Run: func(cmd *cobra.Command, args []string) {
					assert.NotEmpty(t, *testString)
					assert.NotEmpty(t, *testInt)
					assert.NotEmpty(t, subcommandBool)
					subCommandExecuted = true
				},
			}
			subCmd.Flags().BoolVar(&subcommandBool, "test-bool", false, "Subcommand string flag")
			cmd.AddCommand(subCmd)

			v = getViper()

			cmd.SetArgs(tc.args)
			err := cmd.Execute()
			assert.NoError(t, err)

			assert.True(t, subCommandExecuted)
			subCommandExecuted = false
		})
	}
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

func writeTempFile(t *testing.T, content []byte, fileExtension string) string {
	file, err := os.CreateTemp("", "config-*."+fileExtension)
	assert.NoError(t, err)

	_, err = file.Write([]byte(content))
	assert.NoError(t, err)
	assert.NoError(t, file.Close())

	return file.Name()
}

func getViper() *viper.Viper {
	v := viper.New()
	v.SetEnvPrefix(envVarPrefix)

	return v
}
