package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/rules"
	"github.com/zricethezav/gitleaks/v8/config"
)

func GenericCredential() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "generic-api-key",
		Description: "Detected a Generic API Key, potentially exposing access to various services and sensitive operations.",
		Regex: generateSemiGenericRegexIncludingXml([]string{
			"key",
			"api",
			"token",
			"secret",
			"client",
			"passwd",
			"password",
			"auth",
			"access",
		}, `[0-9a-z\-_.=]{10,150}`, true),
		Keywords: []string{
			"key",
			"api",
			"token",
			"secret",
			"client",
			"passwd",
			"password",
			"auth",
			"access",
		},
		Entropy: 3.5,
		Allowlist: config.Allowlist{
			StopWords: rules.DefaultStopWords,
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("generic", "CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443"),
		generateSampleSecret("generic", "Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB"),
		`"client_id" : "0afae57f3ccfd9d7f5767067bc48b30f719e271ba470488056e37ab35d4b6506"`,
		`"client_secret" : "6da89121079f83b2eb6acccf8219ea982c3d79bccc3e9c6a85856480661f8fde",`,

		`<key>client_secret</key>
		<string>6da89121079f83b2eb6acccf8219ea982c3d79bccc3e9c6a85856480661f8fde</string>`,

		`<key>password</key>
		<string>bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=</string>`,

		`<key>password</key>
		<string>bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=</string>`,

		`<key>access_key_FOR_X_SERVICES</key>
		<string>kgfur834kmjfdoi34i9</string>`,
	}
	fps := []string{
		`client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.client-vpn-endpoint.id`,
		`password combination.

R5: Regulatory--21`,

		`<key>AD_UNIT_ID_FOR_BANNER_TEST</key>
<string>ca-app-pub-3940256099942544/2934735716</string>`,
		`<key>AD_UNIT_ID_FOR_INTERSTITIAL_TEST</key>
<string>ca-app-pub-3940256099942544/4411468910</string>`,
		`<key>CLIENT_ID</key>
<string>407966239993-b1h97alknrmf0g846um5pr3a25s9qmeu.apps.googleusercontent.com</string>`,
		`<key>REVERSED_CLIENT_ID</key>
<string>com.googleusercontent.apps.407966239993-b1h97alknrmf0g846um5pr3a25s9qmeu</string>`,
		`<key>GOOGLE_APP_ID</key>
<string>1:407966239993:ios:0d7534f14f8cfe19</string>`,
	}
	return validate(r, tps, fps)
}
