package detect

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
)

const configPath = "../../tests/testData/config/"

func TestDetect(t *testing.T) {
	tests := []struct {
		cfgName      string
		baselinePath string
		fragment     Fragment
		// NOTE: for expected findings, all line numbers will be 0
		// because line deltas are added _after_ the finding is created.
		// I.e., if the finding is from a --no-git file, the line number will be
		// increase by 1 in DetectFromFiles(). If the finding is from git,
		// the line number will be increased by the patch delta.
		expectedFindings []report.Finding
		wantError        error
	}{
		{
			cfgName: "simple",
			fragment: Fragment{
				Raw:      `awsToken := \"AKIALALEMEL33243OKIA\ // gitleaks:allow"`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{},
		},
		{
			cfgName: "simple",
			fragment: Fragment{
				Raw: `awsToken := \

				\"AKIALALEMEL33243OKIA\ // gitleaks:allow"

				`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{},
		},
		{
			cfgName: "simple",
			fragment: Fragment{
				Raw: `awsToken := \"AKIALALEMEL33243OKIA\"

						// gitleaks:allow"

						`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{
				{
					Description: "AWS Access Key",
					Secret:      "AKIALALEMEL33243OKIA",
					Match:       "AKIALALEMEL33243OKIA",
					File:        "tmp.go",
					Line:        `awsToken := \"AKIALALEMEL33243OKIA\"`,
					RuleID:      "aws-access-key",
					Tags:        []string{"key", "AWS"},
					StartLine:   0,
					EndLine:     0,
					StartColumn: 15,
					EndColumn:   34,
					Entropy:     3.1464393,
				},
			},
		},
		{
			cfgName: "escaped_character_group",
			fragment: Fragment{
				Raw:      `pypi-AgEIcHlwaS5vcmcAAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAAB`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{
				{
					Description: "PyPI upload token",
					Secret:      "pypi-AgEIcHlwaS5vcmcAAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAAB",
					Match:       "pypi-AgEIcHlwaS5vcmcAAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAAB",
					Line:        `pypi-AgEIcHlwaS5vcmcAAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAAB`,
					File:        "tmp.go",
					RuleID:      "pypi-upload-token",
					Tags:        []string{"key", "pypi"},
					StartLine:   0,
					EndLine:     0,
					StartColumn: 1,
					EndColumn:   86,
					Entropy:     1.9606875,
				},
			},
		},
		{
			cfgName: "simple",
			fragment: Fragment{
				Raw:      `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{
				{
					Description: "AWS Access Key",
					Secret:      "AKIALALEMEL33243OLIA",
					Match:       "AKIALALEMEL33243OLIA",
					Line:        `awsToken := \"AKIALALEMEL33243OLIA\"`,
					File:        "tmp.go",
					RuleID:      "aws-access-key",
					Tags:        []string{"key", "AWS"},
					StartLine:   0,
					EndLine:     0,
					StartColumn: 15,
					EndColumn:   34,
					Entropy:     3.0841837,
				},
			},
		},
		{
			cfgName: "simple",
			fragment: Fragment{
				Raw:      `export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef;`,
				FilePath: "tmp.sh",
			},
			expectedFindings: []report.Finding{
				{
					Description: "Sidekiq Secret",
					Match:       "BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef;",
					Secret:      "cafebabe:deadbeef",
					Line:        `export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef;`,
					File:        "tmp.sh",
					RuleID:      "sidekiq-secret",
					Tags:        []string{},
					Entropy:     2.6098502,
					StartLine:   0,
					EndLine:     0,
					StartColumn: 8,
					EndColumn:   60,
				},
			},
		},
		{
			cfgName: "simple",
			fragment: Fragment{
				Raw:      `echo hello1; export BUNDLE_ENTERPRISE__CONTRIBSYS__COM="cafebabe:deadbeef" && echo hello2`,
				FilePath: "tmp.sh",
			},
			expectedFindings: []report.Finding{
				{
					Description: "Sidekiq Secret",
					Match:       "BUNDLE_ENTERPRISE__CONTRIBSYS__COM=\"cafebabe:deadbeef\"",
					Secret:      "cafebabe:deadbeef",
					File:        "tmp.sh",
					Line:        `echo hello1; export BUNDLE_ENTERPRISE__CONTRIBSYS__COM="cafebabe:deadbeef" && echo hello2`,
					RuleID:      "sidekiq-secret",
					Tags:        []string{},
					Entropy:     2.6098502,
					StartLine:   0,
					EndLine:     0,
					StartColumn: 21,
					EndColumn:   74,
				},
			},
		},
		{
			cfgName: "simple",
			fragment: Fragment{
				Raw:      `url = "http://cafeb4b3:d3adb33f@enterprise.contribsys.com:80/path?param1=true&param2=false#heading1"`,
				FilePath: "tmp.sh",
			},
			expectedFindings: []report.Finding{
				{
					Description: "Sidekiq Sensitive URL",
					Match:       "http://cafeb4b3:d3adb33f@enterprise.contribsys.com:",
					Secret:      "cafeb4b3:d3adb33f",
					File:        "tmp.sh",
					Line:        `url = "http://cafeb4b3:d3adb33f@enterprise.contribsys.com:80/path?param1=true&param2=false#heading1"`,
					RuleID:      "sidekiq-sensitive-url",
					Tags:        []string{},
					Entropy:     2.984234,
					StartLine:   0,
					EndLine:     0,
					StartColumn: 8,
					EndColumn:   58,
				},
			},
		},
		{
			cfgName: "allow_aws_re",
			fragment: Fragment{
				Raw:      `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{},
		},
		{
			cfgName: "allow_path",
			fragment: Fragment{
				Raw:      `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{},
		},
		{
			cfgName: "allow_commit",
			fragment: Fragment{
				Raw:       `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath:  "tmp.go",
				CommitSHA: "allowthiscommit",
			},
			expectedFindings: []report.Finding{},
		},
		{
			cfgName: "entropy_group",
			fragment: Fragment{
				Raw:      `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{
				{
					Description: "Discord API key",
					Match:       "Discord_Public_Key = \"e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5\"",
					Secret:      "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5",
					Line:        `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
					File:        "tmp.go",
					RuleID:      "discord-api-key",
					Tags:        []string{},
					Entropy:     3.7906237,
					StartLine:   0,
					EndLine:     0,
					StartColumn: 7,
					EndColumn:   93,
				},
			},
		},
		{
			cfgName: "generic_with_py_path",
			fragment: Fragment{
				Raw:      `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{},
		},
		{
			cfgName: "generic_with_py_path",
			fragment: Fragment{
				Raw:      `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				FilePath: "tmp.py",
			},
			expectedFindings: []report.Finding{
				{
					Description: "Generic API Key",
					Match:       "Key = \"e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5\"",
					Secret:      "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5",
					Line:        `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
					File:        "tmp.py",
					RuleID:      "generic-api-key",
					Tags:        []string{},
					Entropy:     3.7906237,
					StartLine:   0,
					EndLine:     0,
					StartColumn: 22,
					EndColumn:   93,
				},
			},
		},
		{
			cfgName: "bad_entropy_group",
			fragment: Fragment{
				Raw:      `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{},
			wantError:        fmt.Errorf("Discord API key invalid regex secret group 5, max regex secret group 3"),
		},
		{
			cfgName: "simple",
			fragment: Fragment{
				Raw:      `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath: filepath.Join(configPath, "simple.toml"),
			},
			expectedFindings: []report.Finding{},
		},
		{
			cfgName: "allow_global_aws_re",
			fragment: Fragment{
				Raw:      `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{},
		},
		{
			cfgName: "generic_with_py_path",
			fragment: Fragment{
				Raw:      `const Discord_Public_Key = "load2523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				FilePath: "tmp.py",
			},
			expectedFindings: []report.Finding{},
		},
	}

	for i, tt := range tests {
		viper.Reset()
		viper.AddConfigPath(configPath)
		viper.SetConfigName(tt.cfgName)
		viper.SetConfigType("toml")
		err := viper.ReadInConfig()
		require.NoError(t, err)

		var vc config.ViperConfig
		err = viper.Unmarshal(&vc)
		require.NoError(t, err)
		cfg, err := vc.Translate()
		cfg.Path = filepath.Join(configPath, tt.cfgName+".toml")
		assert.Equal(t, tt.wantError, err)
		d := NewDetector(&cfg)
		d.baselinePath = tt.baselinePath

		findings := d.Detect(&tt.fragment)
		if len(findings) != len(tt.expectedFindings) {
			t.Logf("[DEBUG] Test case #%d: cfgName=%s, FilePath=%s", i, tt.cfgName, tt.fragment.FilePath)
			t.Logf("[DEBUG] Expected findings: %+v", tt.expectedFindings)
			t.Logf("[DEBUG] Actual findings:   %+v", findings)
		}
		assert.ElementsMatch(t, tt.expectedFindings, findings)
	}
}
