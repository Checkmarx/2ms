package rules_test

import (
	"regexp"
	"testing"

	"github.com/checkmarx/2ms/v4/engine/rules"
	gitleaksrules "github.com/zricethezav/gitleaks/v8/cmd/generate/config/rules"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Test2msRules(t *testing.T) {
	t.Parallel()

	testsRules := []struct {
		name     string
		validate func()
	}{
		{name: "Atlassian", validate: validateAtlassian},
		{name: "AwsAccessToken", validate: validateAwsAccessToken},
		{name: "AuthenticatedURL", validate: validateAuthenticatedURL},
		{name: "Clojars", validate: validateClojars},
		{name: "GenericCredential", validate: validateGenericCredential},
		{name: "GitHubApp", validate: validateGitHubApp},
		{name: "GitlabPatRoutable", validate: validateGitlabPatRoutable},
		{name: "GitlabRunnerAuthenticationTokenRoutable", validate: validateGitlabRunnerAuthenticationTokenRoutable},
		{name: "HardcodedPassword", validate: validateHardcodedPassword},
		{name: "OnePasswordSecretKey", validate: validateOnePasswordSecretKey},
		{name: "PlaidAccessID", validate: validatePlaidAccessID},
		{name: "PrivateKey", validate: validatePrivateKey},
		{name: "SumoLogicAccessID", validate: validateSumoLogicAccessID},
		{name: "SumoLogicAccessToken", validate: validateSumoLogicAccessToken},
		{name: "VaultServiceToken", validate: validateVaultServiceToken},
	}

	for _, tRule := range testsRules {
		t.Run(tRule.name, func(t *testing.T) {
			t.Parallel()

			tRule.validate()
		})
	}
}

func validateAtlassian() {
	// Fixed validation - simplified test cases that should match the regex pattern
	tps := []string{
		`atlassian_TOKEN := "abcd1234567890123456abcd"`,   // 24 chars: format [a-z0-9]{20}[a-f0-9]{4}
		`CONFLUENCE_API_KEY = "test1234567890123456beef"`, // 24 chars: format [a-z0-9]{20}[a-f0-9]{4}
		`jira_token = "jira1234567890123456cafe"`,         // 24 chars: format [a-z0-9]{20}[a-f0-9]{4}
		`JIRA_API_TOKEN=HXe8DGg1iJd2AopzyxkFB7F2`,         // Keep the existing 24-char token from GitLeaks
		// Modern ATATT3 tokens (192 characters) - must be on single line
		`ATATT3xFfGF0K3irG5tKKi-6u-wwaXQFeGwZ-IHR-hQ3CulkKtMSuteRQFfLZ6jihHThzZCg_UjnDt-4Wl_gIRf4zrZJs5JqaeuBhsfJ4W5GD6yGg3W7903gbvaxZPBjxIQQ7BgFDSkPS8oPispw4KLz56mdK-G6CIvLO6hHRrZHY0Q3tvJ6JxE=C63992E6`, //nolint:lll
	}

	fps := []string{"getPagesInConfluenceSpace,searchConfluenceUsingCql"}

	utils.Validate(*rules.Atlassian(), tps, fps)
}

func validateAuthenticatedURL() {
	tPositives := []string{
		"mongodb+srv://radar:mytoken@io.dbb.mongodb.net/?retryWrites=true&w=majority",
		"--output=https://elastic:bF21iC0bfTVXo3qhpJqTGs78@c22f5bc9787c4c268d3b069ad866bdc2.eu-central-1.aws.cloud.es.io:9243/tfs",
		"https://abc:123@google.com",
	}

	fPositives := []string{
		"https://google.com",
		"https://google.com?user=abc&password=123",
		`<img src="https://img.shields.io/static/v1?label=Threads&message=Follow&color=101010&` +
			`link=https://threads.net/@mathrunet" alt="Follow on Threads" />`,
		`my [Linkedin](https://www.linkedin.com/in/rodriguesjeffdev/) or email: rodriguesjeff.dev@gmail.com`,
		`[![Gmail Badge](https://img.shields.io/badge/-VaibhavHariramani-d54b3d?style=flat-circle&labelColor=d54b3d&` +
			`logo=gmail&logoColor=white&link=mailto:vaibhav.hariramani01@gmail.com)](mailto:vaibhav.hariramani01@gmail.com)`,
		`https://situmops:$(github_token)@github.com/$(Build.Repository.Name).git`,
		`'$cmd "unilinks://@@malformed.invalid.url/path?"$cmdSuffix',`,
		`Uri.parse('http://login:password@192.168.0.1:8888'),`,
	}

	utils.Validate(*rules.AuthenticatedURL(), tPositives, fPositives)
}

func validateClojars() {
	// validate
	tps := []string{
		utils.GenerateSampleSecret("clojars", "CLOJARS_"+secrets.NewSecret(utils.AlphaNumeric("60"))),
	}
	utils.Validate(*rules.Clojars(), tps, nil)
}

func validateGenericCredential() {
	var (
		newPlausibleSecret = func(regex string) string {
			allowList := &config.Allowlist{StopWords: gitleaksrules.DefaultStopWords}
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
	)
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AD_UNIT_ID_FOR_BANNER_TEST</key>
	<string>asdfasdfasd</string>
	<key>AD_UNIT_ID_FOR_INTERSTITIAL_TEST</key>
	<string>asdffasdf</string>
	<key>CLIENT_ID</key>
	<string>asdk34ofko3kdl,3o,kodk3ok3dd3e</string>
	<key>REVERSED_CLIENT_ID</key>
	<string>asdfasdfasdf</string>
	<key>API_KEY</key>
	<string>AIzaSyATDL7Wz3De6BUF12v3fVVth30vkyis21h</string>
	<key>GCM_SENDER_ID</key>
	<string>407966239993</string>
	<key>PLIST_VERSION</key>
	<string>1</string>
</dict>
</plist>`

	tps := utils.GenerateSampleSecrets("generic", "CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443") //gitleaks:allow
	tps = append(tps, utils.GenerateSampleSecrets("generic", "Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB")...)
	tps = append(tps,
		// Access
		`'access_token': 'eyJ0eXAioiJKV1slS3oASx=='`,

		// API
		`some_api_token_123 = "`+newPlausibleSecret(`[a-zA-Z0-9]{60}`)+`"`,

		// Auth
		`"user_auth": "am9obmRvZTpkMDY5NGIxYi1jMTcxLTQ4ODYt+TMyYS0wMmUwOWQ1/mIwNjc="`,

		// Credentials
		`"credentials" : "0afae57f3ccfd9d7f5767067bc48b30f719e271ba470488056e37ab35d4b6506"`,
		`creds = `+newPlausibleSecret(`[a-zA-Z0-9]{30}`),

		// Key
		`private-key: `+newPlausibleSecret(`[a-zA-Z0-9\-_.=]{100}`),

		// Password
		`passwd = `+newPlausibleSecret(`[a-zA-Z0-9\-_.=]{30}`),
		// TODO: `ID=dbuser;password=` + newPlausibleSecret(`[a-zA-Z0-9+/]{30}={0,3}`) + `;"`,

		// Secret
		`"client_secret" : "6da89121079f83b2eb6acccf8219ea982c3d79bccc3e9c6a85856480661f8fde",`,
		`mySecretString=`+newPlausibleSecret(`[a-zA-Z0-9]{30}`),
		`todo_secret_do_not_commit = `+newPlausibleSecret(`[a-zA-Z0-9]{30}`),
		xml,

		// Token
		` utils.GetEnvOrDefault("api_token", "dafa7817-e246-48f3-91a7-e87653d587b8")`,
		//	`"env": {
		//"API_TOKEN": "Lj2^5O%xi214"`,
	)
	fps := []string{
		// Access
		`"accessor":"rA1wk0Y45YCufyfq",`,
		`report_access_id: e8e4df51-2054-49b0-ab1c-516ac95c691d`,
		`accessibilityYesOptionId = "0736f5ef-7e88-499a-80cc-90c85d2a5180"`,
		`_RandomAccessIterator>
_LIBCPP_CONSTEXPR_AFTER_CXX11 `,

		// API
		`this.ultraPictureBox1.Name = "ultraPictureBox1";`,
		`rapidstring:marm64-uwp=fail`,
		`event-bus-message-api:rc0.15.0_20231217_1420-SNAPSHOT'`,
		`COMMUNICATION_API_VERSION=rc0.13.0_20230412_0712-SNAPSHOT`,
		`MantleAPI_version=9a038989604e8da62ecddbe2094b16ce1b778be1`,
		`[DEBUG]		org.slf4j.slf4j-api:jar:1.7.8.:compile (version managed from default)`,
		`[DEBUG]		org.neo4j.neo4j-graphdb-api:jar:3.5.12:test`,
		`apiUrl=apigee.corpint.com`,
		`X-API-Name": "NRG0-Hermes-INTERNAL-API",`,
		// TODO: Jetbrains IML files (requires line-level allowlist).
		// `<orderEntry type="library" scope="PROVIDED" name="Maven: org.apache.directory.api:api-asn1-api:1.0.0-M20" level="projcet" />`

		// Auth
		`author = "james.fake@ymail.com",`,
		`X-MS-Exchange-Organization-AuthSource: sm02915.int.contoso.com`,
		`Authentication-Results: 5h.ca.iphmx.com`,

		// Credentials
		`withCredentials([usernamePassword(credentialsId: '29f63271-dc2f-4734-8221-5b31b5169bac', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD')]) {`,
		`credentialsId: 'ff083f76-7804-4ef1-80e4-fe975bb9141b'`,
		`jobCredentialsId: 'f4aeb6bc-2a25-458a-8111-9be9e502c0e7'`,
		`  "credentialId": "B9mTcFSck2LzJO2S3ols63",`,
		`environment {
	CREDENTIALS_ID = "K8S_CRED"
}`,
		`dev.credentials.url=dev-lb1.api.f4ke.com:5215`,

		// Key
		`keyword: "Befaehigung_P2"`,
		`public_key = "9Cnzj4p4WGeKLs1Pt8QuKUpRKfFLfRYC9AIKjbJTWit"`,
		`pub const X509_pubkey_st = struct_X509_pubkey_st;`,
		`|| pIdxKey->default_rc==0`,
		`monkeys-audio:mx64-uwp=fail`,
		`primaryKey=` + newPlausibleSecret(`[a-zA-Z0-9\-_.=]{30}`),
		`foreignKey=` + newPlausibleSecret(`[a-zA-Z0-9\-_.=]{30}`),
		`key_down_event=` + newPlausibleSecret(`[a-zA-Z0-9\-_.=]{30}`),
		`issuerKeyHash=` + newPlausibleSecret(`[a-zA-Z0-9\-_.=]{30}`),
		`<entry key="jetbrains.mps.v8_elimination" value="executed" />`,
		`minisat-master-keying:x64-uwp=fail`,
		`IceSSL.KeyFile=s_rsa1024_priv.pem`,
		`"bucket_key": "SalesResults-1.2"`,
		`<key tag="SecurityIdentifier" name="SecurityIdentifier" type="STRING" />`,
		// `packageKey":` + newPlausibleSecret(`[a-zA-Z0-9\-_.=]{30}`),
		`schemaKey = 'DOC_Vector_5_32'`,
		`sequenceKey = "18"`,
		`app.keystore.file=env/cert.p12`,
		`-DKEYTAB_FILE=/tmp/app.keytab`,
		`	doc.Security.KeySize = PdfEncryptionKeySize.Key128Bit;`,
		`o.keySelector=n,o.haKey=!1,`,
		// TODO: Requires line-level allowlists.
		`                                "key_name": "prod5zyxlmy-cmk",`,
		`                                "kms_key_id": "555ea4a3-d53a-4412-9c66-3a7cb667b0d6",`,
		`	"key_vault_name": "web21prqodx24021",`,
		`  keyVaultToStoreSecrets: cmp2-qat-1208358310`, // e.g., https://github.com/2uasimojo/community-operators-prod/blob/9e51e4c8e0b5caaa3087e8e18e6fb918b2c36643/operators/azure-service-operator/1.0.59040/manifests/azure.microsoft.com_cosmosdbs.yaml#L50
		`,apiKey:"6fe4476ee5a1832882e326b506d14126",`,
		`const validKeyChars = "0123456789abcdefghijklmnopqrstuvwxyz_-."`,
		`const keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"`,
		`key_length = XSalsa20.key_length`,
		`pub const SN_id_Gost28147_89_None_KeyMeshing = "id-Gost28147-89-None-KeyMeshing"`,
		`KeyPair = X25519.KeyPair`,
		`BlindKeySignatures = Ed25519.BlindKeySignatures`,
		`AVEncVideoMaxKeyframeDistance, "2987123a-ba93-4704-b489-ec1e5f25292c"`,
		`            keyPressed = kVK_Return.u16`,
		`timezone_mapping = {
    "Turkey Standard Time": "Europe/Istanbul",
}`, // https://github.com/gitleaks/gitleaks/issues/1799
		// `<add key="SchemaTable" value="G:\SchemaTable.xml" />`,
		//`    { key: '9df21e95-3848-409d-8f94-c675cdfee839', value: 'Americas' },`,
		// `<TAR key="REF_ID_923.properties" value="/opts/config/alias/"/>`,
		//	`secret:
		// secretName: app-decryption-secret
		// items:
		//	- key: app-k8s.yml
		//	  path: app-k8s.yml`,

		// TODO: https://learn.microsoft.com/en-us/windows/apps/design/style/xaml-theme-resources
		//`<Color x:Key="NormalBrushGradient1">#FFBAE4FF</Color>`,

		// Password
		`password combination.

R5: Regulatory--21`,
		`PuttyPassword=0`,

		// Secret
		`LLM_SECRET_NAME = "NEXUS-GPT4-API-KEY"`,
		`  <UserSecretsId>79a3edd0-2092-40a2-a04d-dcb46d5ca9ed</UserSecretsId>`,
		`secret_length = X25519.secret_length`,
		`secretSize must be >= XXH3_SECRET_SIZE_MIN`,
		`# get build time secret for authentication
#RUN --mount=type=secret,id=jfrog_secret \
#    JFROG_SECRET = $(cat /run/secrets/jfrog_secret) && \`,

		// Token
		`    access_token_url='https://github.com/login/oauth/access_token',`,
		`publicToken = "9Cnzj4p4WGeKLs1Pt8QuKUpRKfFLfRYC9AIKjbJTWit"`,
		`<SourceFile SourceLocation="F:\Extracts\" TokenFile="RTL_INST_CODE.cer">`,
		`notes            = "Maven - io.jsonwebtoken:jjwt-jackson-0.11.2"`,
		`csrf-token=Mj2qykJO5rELyHgezQ69nzUX0i3OH67V7+V4eUrLfpuyOuxmiW9rhROG/Whikle15syazJOkrjJa3U2AbhIvUw==`,
		// TODO: `TOKEN_AUDIENCE = "25872395-ed3a-4703-b647-22ec53f3683c"`,

		// General
		`clientId = "73082700-1f09-405b-80d0-3131bfd6272d"`,
		`GITHUB_API_KEY=
DYNATRACE_API_KEY=`,
		`snowflake.password=
jdbc.snowflake.url=`,
		`import { chain_Anvil1_Key, chain_Anvil2_Key } from '../blockchain-tests/pallets/supported-chains/consts';`,

		// Yocto/BitBake
		`SRCREV_moby = "43fc912ef59a83054ea7f6706df4d53a7dea4d80"`,
		`LIC_FILES_CHKSUM = "file://${WORKDIR}/license.html;md5=5c94767cedb5d6987c902ac850ded2c6"`,
	}
	utils.Validate(*rules.GenericCredential(), tps, fps)
}

func validateGitHubApp() {
	// validate
	tps := []string{
		utils.GenerateSampleSecret("github", "ghu_"+secrets.NewSecret(utils.AlphaNumeric("36"))),
		utils.GenerateSampleSecret("github", "ghs_"+secrets.NewSecret(utils.AlphaNumeric("36"))),
	}
	utils.Validate(*rules.GitHubApp(), tps, nil)
}

func validateHardcodedPassword() {
	tPositives := []string{
		`"client_id" : "0afae57f3ccfd9d7f5767067bc48b30f719e271ba470488056e37ab35d4b6506"`,
		`"client_secret" : "6da89121079f83b2eb6acccf8219ea982c3d79bccc3e9c6a85856480661f8fde",`,
		`"password: 'edf8f16608465858a6c9e3cccb97d3c2'"`,
		`<element password="edf8f16608465858a6c9e3cccb97d3c2" />`,
		`"client_id" : "edf8f16608465858a6c9e3cccb97d3c2"`,
		"https://google.com?user=abc&password=1234",
		`{ "access-key": "6da89121079f83b2eb6acccf8219ea982c3d79bccc", }`,
		`"{ \"access-key\": \"6da89121079f83b2eb6acccf8219ea982c3d79bccc\", }"`,
		"<password>edf8f16608465858a6c9e3cccb97d3c2</password>",
		"M_DB_PASSWORD= edf8f16608465858a6c9e3cccb97d3c2",
		`"client_secret" : "4v7b9n2k5h",`, // entropy: 3.32
		`"password: 'comp123!'"`,
		"<password>MyComp9876</password>", // entropy: 3.32
		`<element password="Comp4567@@" />`,
		"M_DB_PASSWORD= edf8f16608465858a6c9e3cccb97d3c2",
	}

	fPositives := []string{
		`client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.client-vpn-endpoint.id`,
		`password combination.

               R5: Regulatory--21`,
		"GITHUB_TOKEN: ${GITHUB_TOKEN}",
		"password = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'", // Stop word
		"password = 'your_password_here'",               // Stop word

	}

	utils.Validate(*rules.HardcodedPassword(), tPositives, fPositives)
}

func validatePlaidAccessID() {
	// validate
	tps := []string{
		utils.GenerateSampleSecret("plaid", secrets.NewSecret(utils.AlphaNumeric("24"))),
	}
	utils.Validate(*rules.PlaidAccessID(), tps, nil)
}

func validatePrivateKey() {
	tps := []string{`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAC4AWkdwKYSd8
Ks14IReLcYgADhoXk56ZzXI=
-----END PRIVATE KEY-----`,
		`-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAn6/O8li+SX4m98LLYt/PKSzEmQ++ZBD7Loh9P13f4yQ92EF3
yxR5MsXFu9PRsrYQA7/4UTPHiC4y2sAVCBg4C2yyBpUEtMQjyCESi6Y=
-----END RSA PRIVATE KEY-----
`,
		`-----BEGIN PGP PRIVATE KEY BLOCK-----
lQWGBGSVV4YBDAClvRnxezIRy2Yv7SFlzC0iFiRF/O/jePSw+XYhvcrTaqSYTGic
=8xQN
-----END PGP PRIVATE KEY BLOCK-----`,
	} // gitleaks:allow
	fps := []string{
		`-----BEGIN PRIVATE KEY-----
anything
-----END PRIVATE KEY-----`,
		`-----BEGIN OPENSSH PRIVATE KEY----------END OPENSSH PRIVATE KEY-----`,
	}
	utils.Validate(*rules.PrivateKey(), tps, fps)
}

func validateSumoLogicAccessID() {
	// Comment validation because it's flaky due to wrong generation of regexes.
	// tps := utils.GenerateSampleSecrets("sumo", secrets.NewSecret(`su[a-zA-Z0-9]{12}`))
	tps := []string{}
	tps = append(tps,
		`sumologic.accessId = "su9OL59biWiJu7"`,      // 14 chars: su + 12 alphanumeric
		`sumologic_access_id = "sug5XpdpaoxtOH"`,     // 14 chars: su + 12 alphanumeric
		`export SUMOLOGIC_ACCESSID="suDbJw97o9WVo0"`, // 14 chars: su + 12 alphanumeric
		`SUMO_ACCESS_ID = "suGyI5imvADdvU"`,          // 14 chars: su + 12 alphanumeric
	)

	fps := []string{
		`- (NSNumber *)sumOfProperty:(NSString *)property;`,
		`- (NSInteger)sumOfValuesInRange:(NSRange)range;`,
		`+ (unsigned char)byteChecksumOfData:(id)arg1;`,
		`sumOfExposures = sumOfExposures;`,
		`.si-sumologic.si--color::before { color: #000099; }`,
		`/// Based on the SumoLogic keyword syntax:`,
		`sumologic_access_id         = ""`,
		`SUMOLOGIC_ACCESSID: ${SUMOLOGIC_ACCESSID}`,
		`export SUMOLOGIC_ACCESSID=XXXXXXXXXXXXXX`,
		`sumObj = suGyI5imvADdvU`,
	}

	utils.Validate(*rules.SumoLogicAccessID(), tps, fps)
}

func validateSumoLogicAccessToken() {
	// Fixed validation - use the same pattern as original GitLeaks
	tps := utils.GenerateSampleSecrets("sumo", secrets.NewSecret(utils.AlphaNumeric("64")))
	tps = append(tps,
		`export SUMOLOGIC_ACCESSKEY="3HSa1hQfz6BYzlxf7Yb1WKG3Hyovm56LMFChV2y9LgkRipsXCujcLb5ej3oQUJlx"`, // 64 alphanumeric chars
		`SUMO_ACCESS_KEY: gxq3rJQkS6qovOg9UY2Q70iH1jFZx0WBrrsiAYv4XHodogAwTKyLzvFK4neRN8Dk`,             // 64 alphanumeric chars
		`SUMOLOGIC_ACCESSKEY: 9RITWb3I3kAnSyUolcVJq4gwM17JRnQK8ugRaixFfxkdSl8ys17ZtEL3LotESKB7`,         // 64 alphanumeric chars
		`sumo_access_key = "3Kof2VffNQ0QgYIhXUPJosVlCaQKm2hfpWE6F1fT9YGY74blQBIPsrkCcf1TwKE5"`,          // 64 alphanumeric chars
	)

	fps := []string{
		`#   SUMO_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
		"-e SUMO_ACCESS_KEY=`etcdctl get /sumologic_secret`",
		`SUMO_ACCESS_KEY={SumoAccessKey}`,
		`SUMO_ACCESS_KEY=${SUMO_ACCESS_KEY:=$2}`,
		`sumo_access_key   = "<SUMOLOGIC ACCESS KEY>"`,
		`SUMO_ACCESS_KEY: AbCeFG123`,
		`sumOfExposures = 3Kof2VffNQ0QgYIhXUPJosVlCaQKm2hfpWE6F1fT9YGY74blQBIPsrkCcf1TwKE5;`,
	}

	utils.Validate(*rules.SumoLogicAccessToken(), tps, fps)
}

func validateVaultServiceToken() {
	// validate
	tps := []string{
		utils.GenerateSampleSecret("vault", "hvs."+secrets.NewSecret(utils.AlphaNumericExtendedShort("90"))),
	}
	utils.Validate(*rules.VaultServiceToken(), tps, nil)
}

func validateGitlabPatRoutable() {
	tps := utils.GenerateSampleSecrets("gitlab", "glpat-"+secrets.NewSecret(utils.AlphaNumeric("27"))+"."+secrets.NewSecret(utils.AlphaNumeric("2"))+secrets.NewSecret(utils.AlphaNumeric("7")))
	fps := []string{
		"glpat-xxxxxxxx-xxxxxxxxxxxxxxxxxx.xxxxxxxxx",
	}
	utils.Validate(*rules.GitlabPatRoutable(), tps, fps)
}

func validateGitlabRunnerAuthenticationTokenRoutable() {
	tps := utils.GenerateSampleSecrets("gitlab", "glrt-t"+secrets.NewSecret(utils.Numeric("1"))+"_"+secrets.NewSecret(utils.AlphaNumeric("27"))+"."+secrets.NewSecret(utils.AlphaNumeric("2"))+secrets.NewSecret(utils.AlphaNumeric("7")))
	fps := []string{
		"glrt-tx_xxxxxxxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxx",
	}
	utils.Validate(*rules.GitlabRunnerAuthenticationTokenRoutable(), tps, fps)
}

func validateAwsAccessToken() {
	tps := utils.GenerateSampleSecrets("AWS", "AKIALALEMEL33243OLIB") // gitleaks:allow
	// current AWS tokens cannot contain [0,1,8,9], so their entropy is slightly lower than expected.
	tps = append(tps, utils.GenerateSampleSecrets("AWS", "AKIA"+secrets.NewSecret("[A-Z2-7]{16}"))...)
	tps = append(tps, utils.GenerateSampleSecrets("AWS", "ASIA"+secrets.NewSecret("[A-Z2-7]{16}"))...)
	tps = append(tps, utils.GenerateSampleSecrets("AWS", "ABIA"+secrets.NewSecret("[A-Z2-7]{16}"))...)
	tps = append(tps, utils.GenerateSampleSecrets("AWS", "ACCA"+secrets.NewSecret("[A-Z2-7]{16}"))...)
	fps := []string{
		`key = AKIAXXXXXXXXXXXXXXXX`,           // Low entropy
		`aws_access_key: AKIAIOSFODNN7EXAMPLE`, // Placeholder
		`msgstr "Näytä asiakirjamallikansio."`, // Lowercase
		`TODAYINASIAASACKOFRICEFELLOVER`,       // wrong length
		`CTTCATAGGGTTCACGCTGTGTAAT-ACG--CCTGAGGC-CACA-AGGGGACTTCAGCAACCGTCGGG-GATTC-ATTGCCA-A--TGGAAGCAATC-TA-TGGGTTA-TCGCGGAGTCCGCAAAGACGGCCAGTATG-AAGCAGATTTCGCAC-CAATGTGACTGCATTTCGTG-ATCGGGGTAAGTA-TC-GCCGATTC-GC--CCGTCCA-AGT-CGAAG-TA--GGCAATATAAAGCTGC-CATTGCCGAAGCTATCTCGCTA-TACTTGAT-AATCGGCGG-TAG-CACAG-GTCGCAGTATCG-AC-T--AGG-CCTCTCAAAAGTT-GGGTCCCGGCCTCTGGGAAAAACACCTCT-A-AGCGTCAATCAGCTCGGTTTCGCATATTA-TGATATCCCCCGTTGACCAATTGA--TAGTACCCGAGCTTACCGTCGG-ATTCTGGAGTCTT-ATGAGGTTACCGACGA-CGCAGTACCATAAGT-GCGCAATTTGACTGTTCCCGTCGAGTAACCA-AGCTTTGCTCA-CCGGGATGCGCGCCGATGTGACCAGGGGGCGCATGTTACATTGAC-A-GCTGGATCATGTTATGAC-GTGGGTC-ATGCTAAAAGCCTAAAGGACGGT-GCATTAGTAT-TACCGGGACCTCATATCAATGCGCTCGCTAGTTCCTCTTCTCTTGATAACGTATATGCGTCAGGCGCCCGTCCGCCTCCAATACGTG-ACAACGTC-AGTACTGAGCCTC--AA-ACATCGTCTTGTTCG-CC-TACAAAGGATCGGTAGAAAACTCAATATTCGGGTATAAGGTCGTAGGAAGTGTGTCGCCCAGGGCCG-CTAGA-AGCGCACACAAGCG-CTCCTGTCAAGGAGTTG-GTGAAAA-ATGAAC--GACT-ATTGCGTCAC--CTACCTCT-AAGTTTTT-GACAATTTCATGGACGAATTGA-AGCGTCCACAAGCATCTGCCGTAGATATGCGGTAGGTTTTTACATATG-TCACTGCAGAGTCACGGACA-CACATCGCTGTCAAAATGCTCGTACCTAGT-GT-TTGCGATCCCCC-GCGGCATTA-TCTTTTGAACCCTCGTCCCTGTGG-CTCTGATGATTGAG-GTCTGTA-TTCCCTCGTTGTGGGGGGATTGGACCTT-TGTATAGGTTCTTTAACCG-ATGGGGGGCCG--ATCGA-A-TA-TGCTCCTGTTTGCCCCGAACCTT-ACCTCGG-TCCAGACA-CTAAGAAAAACCCC-C-ACTGTAAGGTGCTGAGCCTTTGGATAGCC-CGCGAATGAT-CC-TAGTTGACAA-CTGAACGCGCTCGAACA-TGCCC-GCCCTCTGA--CTGCTGTCTG-GCACCTTTAGACACGCGTCGAC-CATATATT-AGCGCTGTCTGTGG-AGGT-TGTGTCTTGTTGCTCA-CT-CATTATCTGT-AACTGGCTCC-CTC-CCAT-TGGCGTCTTTACACCAACCGCTAGGTTACAGTGCA-TCTAGCGCCTATTATCAGGGCGT-TTGCAGCGGCGCGGTGGCTATGT-GTTAGACATATC-CTTACACTGTATGCTAG-AGCAAGCCAC-TCTGAATGGGTTGC-CGATGAATGA-TCTTGATC-GAGCTCGCA-AC---TACATGGAGTCCGAAGTGAACCTACGGATGATCGTATTCCAACACGAGGATC-TATACGTATAGG-A-GGCG-TAATCCACAATTTAGTAACTCTTGACGC---GGATGAAAAT-GTCGTTACACCTTCCAGAGGCTCGG-GTATATATATGACCT--TGTGATTGAGGACGATCTAGAATAA-CT-GT-G-CT-AAAGTACAGTAGTTTCTATGT-GGTAGGTGGAGAATACAGAGTAG-ATGATTC-GTGGGCCACA-C--T-ACTTTCAT-TAGAGCAGAGA-C-GTGAGTGAGTTTTACACTAGCCAGATGGACCG-GTGA-AGTCTAACAGCCACCGCTT-GTGAGGTCGTTTCCCAGTC-ACCCTACTACAGGCAAAAACTCAGTGT-CC-GTGA-GTGCGTTAGTGATATTCCCTAACGGTTAGGTAACT-CATGAATTCA-AT-TAAGCGTGTCC-CGGT-CACGCCCCCATGGGGGCCTTCTTGGGAGG--AGCATCTTAT--AT-GCTCACGTGGTT-GATAGG-A-T-AATACACTTTTAGTCAGTCCATCAATAAC-AAAGGAAC---CAGGTGGTCGCAGATA-TCCCGCTGATATAGCACTGTGTAAACTCAGGTGATA-CTAAGC--GCTCTAAT-ACG-CTTAATGGCAATGCCCAGTTC--ACGACTAGCTTATGAGGCCCAGCTATGGACTGCGGC-GGCATGTCGGC-GATGGTTGCCCTCGCCCTAAATTATGTACGA-T-ACCGCCT-CTTGTTCT-CCGCCCATAGGGT-C--AGCAGGCGATAGACTCCCAGAAATTTCCTCGTCGT-CCGAATAAGACTAACACGACTA-TT-CCTCTAC-GT-G-AA-CTTATCA-CAAATG-GCT-TACC-TAGGTGGTGGCAGATCACTTTCCGGTG-TATTACGAATTGACGCATACCGAC-A-CGC-GCTTGTTGGATAATCGACTCTAACCTCCTCTCTGGCACATGT-GCTGGATTACCTC-TATTTT-TCTCGCTTAG--GGAACG-T-CCTCTGTCGCGTGAG-GTACGTTTCACGGGAG-CGGCTTGTTCATGCCACGTCCATTATCGA-AGTG-C-GTAAGG-A-GAGCCCTA--GACTCTACACGGAAA-TC-AAC-GTAGAAGGCTC-A-CT`,
	}
	utils.Validate(*rules.AWS(), tps, fps)
}

func validateOnePasswordSecretKey() {
	tps := utils.GenerateSampleSecrets("1password", secrets.NewSecret(`A3-[A-Z0-9]{6}-[A-Z0-9]{11}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}`))
	tps = append(tps, utils.GenerateSampleSecrets("1password", secrets.NewSecret(`A3-[A-Z0-9]{6}-[A-Z0-9]{6}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}`))...)
	tps = append(tps,
		// from whitepaper
		`A3-ASWWYB-798JRYLJVD4-23DC2-86TVM-H43EB`,
		`A3-ASWWYB-798JRY-LJVD4-23DC2-86TVM-H43EB`,
	)
	fps := []string{
		// low entropy
		`A3-XXXXXX-XXXXXXXXXXX-XXXXX-XXXXX-XXXXX`,
		// lowercase
		`A3-xXXXXX-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX`,
	}
	utils.Validate(*rules.OnePasswordSecretKey(), tps, fps)
}
