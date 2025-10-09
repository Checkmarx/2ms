package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHuggingFaceAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "HuggingFaceAccessToken validation",
			truePositives: []string{
				"huggingfaceToken=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",
				"$huggingfaceToken .= \"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\"",
				"huggingfaceToken = \"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\"",
				"huggingface_TOKEN = \"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\"",
				"huggingface_TOKEN := \"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\"",
				"huggingface_TOKEN ::= \"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\"",
				"{\n    \"huggingface_token\": \"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\"\n}",
				"{\"config.ini\": \"HUGGINGFACE_TOKEN=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\\nBACKUP_ENABLED=true\"}",
				"<huggingfaceToken>\n    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\n</huggingfaceToken>",
				"huggingface_token: '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'",
				"huggingfaceToken := \"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\"",
				"huggingface_TOKEN :::= \"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\"",
				"huggingface_TOKEN ?= \"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\"",
				"huggingface_token: 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",
				"huggingface_token: \"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\"",
				"var huggingfaceToken string = \"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\"",
				"huggingfaceToken = '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'",
				"System.setProperty(\"HUGGINGFACE_TOKEN\", \"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\")",
				"huggingfaceToken = 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",
				"string huggingfaceToken = \"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\";",
				"huggingfaceToken := `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`",
				"String huggingfaceToken = \"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\";",
				"var huggingfaceToken = \"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\"",
				"  \"huggingfaceToken\" => \"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\"",
				"huggingfaceToken=\"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\"",
				"huggingfaceToken = \"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\"",
				"huggingface-cli login --token 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",
				"huggingface-cli login --token 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",
				"huggingface-cli login --token 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",
				"huggingface-cli login --token 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",
				"huggingface-cli login --token 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",
				"huggingface-cli login --token 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",
				"huggingface-cli login --token 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",
				"huggingface-cli login --token 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",
				"-H \"Authorization: Bearer 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\"",
				"DEV=1 HF_TOKEN=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 poetry run python app.py",
				"use_auth_token='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')",
				"CI_HUB_USER_TOKEN = \"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\"",
				"- Change line 5 and add your Hugging Face token, that is, instead of 'hf_token = \"ADD_YOUR_HUGGING_FACE_TOKEN_HERE\"', you will need to change it to something like'hf_token = \"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\"'",
				"# Not critical, only usable on the sandboxed CI instance.\n\t\tTOKEN = \"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\"",
				"    parser.add_argument(\"--hf_token\", type=str, default='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', help=\"Hugging Face Access Token to access PyAnnote gated models\")",
			},
			falsePositives: []string{
				`- (id)hf_requiredCharacteristicTypesForDisplayMetadata;`,
				`amazon.de#@#div[data-cel-widget="desktop-rhf_SponsoredProductsRemoteRHFSearchEXPSubsK2ClickPagination"]`,
				`                            _kHMSymptomhf_generatedByHomeAppForDebuggingPurposesKey,`,
				`    #define OSCHF_DebugGetExpectedAverageCrystalAmplitude NOROM_OSCHF_DebugGetExpectedAverageCrystalAmplitude`,
				`  M_UINT       (ServingCellPriorityParametersDescription_t,  H_PRIO,  2, &hf_servingcellpriorityparametersdescription_h_prio),`,
				`+HWI-ST565_0092:4:1101:5508:5860#ACTTGA/1
		bb_eeeeegfgffhiiiiiiiiiiihiiiiicgafhf_eefghihhiiiifhifhhdhifhiiiihifdgdhggf\bbceceedbcd
		@HWI-ST565_0092:4:1101:7621:5770#ACTTGA/1`,
				`y{}x|~|}{~}}~|~}||�~|�{��|{}{|~z{}{{|{||{|}|{}{~|y}vjoePbUBJ7&;";  <; :;?!!;<7%$IACa_ecghbfbaebejhahfbhf_ddbficghbgfbhhcghdghfhigiifhhehhdggcgfchf_fgcei^[[.40&54"5666 6`,
				`                    change_dir(cwd)
		subdirs = glob.glob('HF_CAASIMULIAComputeServicesBuildTime.HF*.Linux64')
		if len(subdirs) == 1:`,
				`        os.environ.get("HF_AUTH_TOKEN",
		"hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),`,
				`# HuggingFace API Token https://huggingface.co/settings/tokens
		HUGGINGFACE_API_TOKEN=hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx,`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(HuggingFaceAccessToken())
			d := createSingleRuleDetector(rule)

			// validate true positives if any specified
			for _, truePositive := range tt.truePositives {
				findings := d.DetectString(truePositive)
				assert.GreaterOrEqual(t, len(findings), 1, fmt.Sprintf("failed to detect true positive: %s", truePositive))
			}

			// validate false positives if any specified
			for _, falsePositive := range tt.falsePositives {
				findings := d.DetectString(falsePositive)
				assert.Equal(t, 0, len(findings), fmt.Sprintf("unexpectedly found false positive: %s", falsePositive))
			}
		})
	}
}
