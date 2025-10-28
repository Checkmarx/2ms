package ruledefine

import (
	"fmt"
	"testing"

	"regexp"

	"github.com/stretchr/testify/assert"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func TestGenericCredential(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "GenericCredential validation",
			truePositives: []string{
				"generic_token: \"CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443\"",
				"genericToken := \"CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443\"",
				"genericToken=\"CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443\"",
				"string genericToken = \"CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443\";",
				"genericToken := `CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443`",
				"genericToken = \"CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443\"",
				"System.setProperty(\"GENERIC_TOKEN\", \"CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443\")",
				"generic_TOKEN :::= \"CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443\"",
				"generic_TOKEN ?= \"CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443\"",
				"generic_token: CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443",
				"var genericToken = \"CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443\"",
				"generic_TOKEN = \"CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443\"",
				"generic_TOKEN := \"CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443\"",
				"<genericToken>\n    CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443\n</genericToken>",
				"var genericToken string = \"CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443\"",
				"String genericToken = \"CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443\";",
				"$genericToken .= \"CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443\"",
				"genericToken = 'CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443'",
				"  \"genericToken\" => \"CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443\"",
				"generic_TOKEN ::= \"CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443\"",
				"genericToken = \"CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443\"",
				"genericToken=CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443",
				"genericToken = CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443",
				"{\n    \"generic_token\": \"CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443\"\n}",
				"{\"config.ini\": \"GENERIC_TOKEN=CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443\\nBACKUP_ENABLED=true\"}",
				"generic_token: 'CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443'",
				"var genericToken string = \"Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB\"",
				"genericToken := \"Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB\"",
				"genericToken := `Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB`",
				"String genericToken = \"Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB\";",
				"genericToken = \"Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB\"",
				"genericToken=Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB",
				"{\n    \"generic_token\": \"Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB\"\n}",
				"generic_token: 'Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB'",
				"genericToken = 'Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB'",
				"genericToken = \"Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB\"",
				"System.setProperty(\"GENERIC_TOKEN\", \"Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB\")",
				"generic_TOKEN :::= \"Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB\"",
				"<genericToken>\n    Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB\n</genericToken>",
				"var genericToken = \"Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB\"",
				"generic_TOKEN = \"Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB\"",
				"generic_TOKEN := \"Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB\"",
				"genericToken=\"Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB\"",
				"genericToken = Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB",
				"$genericToken .= \"Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB\"",
				"  \"genericToken\" => \"Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB\"",
				"generic_TOKEN ::= \"Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB\"",
				"generic_TOKEN ?= \"Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB\"",
				"{\"config.ini\": \"GENERIC_TOKEN=Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB\\nBACKUP_ENABLED=true\"}",
				"generic_token: Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB",
				"generic_token: \"Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB\"",
				"string genericToken = \"Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB\";",
				"'access_token': 'eyJ0eXAioiJKV1slS3oASx=='",
				"some_api_token_123 = \"FqyOTAJSdEgjn727oe4lsSJeRvL0rEHgPR4vFpSFsjxuGWB5HYiuveXHmJjF\"",
				"\"user_auth\": \"am9obmRvZTpkMDY5NGIxYi1jMTcxLTQ4ODYt+TMyYS0wMmUwOWQ1/mIwNjc=\"",
				"\"credentials\" : \"0afae57f3ccfd9d7f5767067bc48b30f719e271ba470488056e37ab35d4b6506\"",
				"creds = FqyOTAJSdEgjn727oe4lsSJeRvL0rE",
				"private-key: OHuZ3NYHOVkhOQTbwi-7XRIk.xxJ1BOmjMZfSIi_kfd4eZKtzwyZnySnalWru=s=wQca3=B4SE=rUslhoCwitfKLgN79cWQNtzF6",
				"passwd = OHuZ3NYHOVkhOQTbwi-7XRIk.xxJ1B",
				"\"client_secret\" : \"6da89121079f83b2eb6acccf8219ea982c3d79bccc3e9c6a85856480661f8fde\",",
				"mySecretString=FqyOTAJSdEgjn727oe4lsSJeRvL0rE",
				"todo_secret_do_not_commit = FqyOTAJSdEgjn727oe4lsSJeRvL0rE",
				" utils.GetEnvOrDefault(\"api_token\", \"dafa7817-e246-48f3-91a7-e87653d587b8\")",
				// xml cases
				"<key>API_KEY</key>\n<string>AIzaSyATDL7Wz3Ze6BU31Yv3fVVth30Skyib29g</string>",
			},
			falsePositives: []string{
				"issuerKeyHash=npmXsmT2_C1iJZ-SD7RuL8exZ=6ucd",
				// xml cases
				"<key>AD_UNIT_ID_FOR_BANNER_TEST</key>\n<string>ca-app-pub-3940256099942544/2934735716</string>",
				"<key>AD_UNIT_ID_FOR_INTERSTITIAL_TEST</key>\n<string>ca-app-pub-3940256099942544/4411468910</string>",
				"<key>CLIENT_ID</key>\n<string>407966239993-b1h97alknrmf0g846um5pr3a25s9qmeu.apps.googleusercontent.com</string>",
				"<key>REVERSED_CLIENT_ID</key>\n<string>com.googleusercontent.apps.407966239993-b1h97alknrmf0g846um5pr3a25s9qmeu</string>",
				"<key>GOOGLE_APP_ID</key>\n<string>1:407966239993:ios:0d7534f14f8cfe19</string>",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := TwomsToGitleaksRule(GenericCredential())
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

func newPlausibleSecret(regex string) string {
	allowList := &config.Allowlist{StopWords: DefaultStopWords}
	// attempt to generate a random secret,
	// retrying until it contains at least one digit and no stop words
	// TODO: currently the DefaultStopWords list contains many short words,
	//  so there is a significant chance of generating a secret that contains a stop word
	for {
		secret := secrets.NewSecret(regex)
		if !regexp.MustCompile(`[1-9]`).MatchString(secret) {
			continue
		}
		if ok, _ := allowList.ContainsStopWord(secret); ok {
			continue
		}
		return secret
	}
}
