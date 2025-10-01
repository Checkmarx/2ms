package rules

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHuggingFaceOrganizationApiToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "HuggingFaceAccessToken validation",
			truePositives: []string{
				"huggingface_TOKEN := \"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\"",
				"huggingface_TOKEN :::= \"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\"",
				"huggingfaceToken = \"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\"",
				"huggingfaceToken := `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`",
				"$huggingfaceToken .= \"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\"",
				"huggingfaceToken = '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'",
				"System.setProperty(\"HUGGINGFACE_TOKEN\", \"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\")",
				"huggingfaceToken=\"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\"",
				"{\"config.ini\": \"HUGGINGFACE_TOKEN=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\\nBACKUP_ENABLED=true\"}",
				"string huggingfaceToken = \"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\";",
				"String huggingfaceToken = \"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\";",
				"var huggingfaceToken = \"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\"",
				"huggingface_TOKEN = \"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\"",
				"huggingface_TOKEN ::= \"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\"",
				"huggingface_TOKEN ?= \"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\"",
				"huggingfaceToken=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",
				"<huggingfaceToken>\n    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\n</huggingfaceToken>",
				"huggingface_token: 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",
				"huggingface_token: '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'",
				"huggingface_token: \"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\"",
				"var huggingfaceToken string = \"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\"",
				"huggingfaceToken := \"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\"",
				"  \"huggingfaceToken\" => \"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\"",
				"huggingfaceToken = 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",
				"{\n    \"huggingface_token\": \"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\"\n}",
				"huggingfaceToken = \"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\"",
				"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",
				"`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`",
				"\\'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'\\",
				"def test_private_space(self):\n        hf_token = \"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\"  # Intentionally revealing this key for testing purposes\n        io = gr.load(",
				"hf_token = \"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\"  # Intentionally revealing this key for testing purposes",
				"\"news_train_dataset = datasets.load_dataset('nlpHakdang/aihub-news30k',  data_files = \\\"train_news_text.csv\\\", use_auth_token='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')\\n\",",
				"os.environ['HUGGINGFACEHUB_API_TOKEN'] = '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'",
				"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",
			},
			falsePositives: []string{
				`public static final String API_ORG_EXIST = "APIOrganizationExist";`,
				`const api_org_controller = require('../../controllers/api/index').organizations;`,
				`API_ORG_CREATE("https://qyapi.weixin.qq.com/cgi-bin/department/create?access_token=ACCESS_TOKEN"),`,
				`def test_internal_api_org_inclusion_with_href(api_name, href, expected, monkeypatch, called_with):
		monkeypatch.setattr("requests.sessions.Session.request", called_with)`,
				`    def _api_org_96726c78_4ae3_402f_b08b_7a78c6903d2a(self, method, url, body, headers):
        body = self.fixtures.load("api_org_96726c78_4ae3_402f_b08b_7a78c6903d2a.xml")
        return httplib.OK, body, headers, httplib.responses[httplib.OK]`,
				`<p>You should see a token <code>hf_xxxxx</code> (old tokens are <code>api_XXXXXXXX</code> or <code>api_org_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX</code>).</p>`,
				`  From Hugging Face docs:
		You should see a token hf_xxxxx (old tokens are api_XXXXXXXX or api_org_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx).
		If you do not submit your API token when sending requests to the API, you will not be able to run inference on your private models.`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(HuggingFaceOrganizationApiToken())
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
