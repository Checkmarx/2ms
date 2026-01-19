package ruledefine

import (
	"regexp"

	"github.com/checkmarx/2ms/v5/engine/constants"
)

var genericCredentialRegex = generateSemiGenericRegexIncludingXml([]string{
	"access",
	"auth",
	`(?-i:[Aa]pi|API)`,
	"credential",
	"creds",
	"key",
	"passw(?:or)?d",
	"secret",
	"token",
}, `[\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3}`, true).String()

func GenericCredential() *Rule {
	return &Rule{
		RuleID:      constants.GenericCredentialRuleID,
		RuleName:    "Generic-Api-Key",
		Description: "Detected a Generic API Key, potentially exposing access to various services and sensitive operations.",
		Regex:       genericCredentialRegex,
		Keywords: []string{
			"access",
			"api",
			"auth",
			"key",
			"credential",
			"creds",
			"passwd",
			"password",
			"secret",
			"token",
		},
		Entropy: 3.5,
		AllowLists: []*AllowList{
			{
				// NOTE: this is a goofy hack to get around the fact there golang's regex engine does not support positive lookaheads.
				// Ideally we would want to ensure the secret contains both numbers and alphabetical characters, not just alphabetical characters.
				Regexes: []string{
					regexp.MustCompile(`^[a-zA-Z_.-]+$`).String(),
				},
			},
			{
				Description:    "Allowlist for Generic API Keys",
				MatchCondition: "OR",
				RegexTarget:    "match",
				Regexes: []string{
					regexp.MustCompile(`(?i)(?:` +
						// Access
						`access(?:ibility|or)` +
						`|access[_.-]?id` +
						`|random[_.-]?access` +
						// API
						`|api[_.-]?(?:id|name|version)` + // id/name/version -> not a secret
						`|rapid|capital` + // common words containing "api"
						`|[a-z0-9-]*?api[a-z0-9-]*?:jar:` + // Maven META-INF dependencies that contain "api" in the name.
						// Auth
						`|author` +
						`|X-MS-Exchange-Organization-Auth` + // email header
						`|Authentication-Results` + // email header
						// Credentials
						`|(?:credentials?[_.-]?id|withCredentials)` + // Jenkins plugins
						// IPv4
						`|(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}` +
						// Key
						`|(?:bucket|foreign|hot|idx|natural|primary|pub(?:lic)?|schema|sequence)[_.-]?key` +
						`|(?:turkey)` +
						`|key[_.-]?(?:alias|board|code|frame|id|length|mesh|name|pair|press(?:ed)?|ring|selector|signature|size|stone|storetype|word|up|down|left|right)` + //nolint:lll
						// Azure KeyVault
						`|KeyVault(?:[A-Za-z]*?(?:Administrator|Reader|Contributor|Owner|Operator|User|Officer))\s*[:=]\s*['"]?[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}['"]?` + //nolint:lll
						`|key[_.-]?vault[_.-]?(?:id|name)|keyVaultToStoreSecrets` +
						`|key(?:store|tab)[_.-]?(?:file|path)` +
						`|issuerkeyhash` + // part of ssl cert
						`|(?-i:[DdMm]onkey|[DM]ONKEY)|keying` + // common words containing "key"
						// Secret
						`|(?:secret)[_.-]?(?:length|name|size)` + // name of e.g. env variable
						`|UserSecretsId` + // https://learn.microsoft.com/en-us/aspnet/core/security/app-secrets?view=aspnetcore-8.0&tabs=linux

						// Token
						`|(?:csrf)[_.-]?token` +

						// Maven library coordinates. (e.g., https://mvnrepository.com/artifact/io.jsonwebtoken/jjwt)
						`|(?:io\.jsonwebtoken[ \t]?:[ \t]?[\w-]+)` +

						// General
						`|(?:api|credentials|token)[_.-]?(?:endpoint|ur[il])` +
						`|public[_.-]?token` +
						`|(?:key|token)[_.-]?file` +
						// Empty variables capturing the next line (e.g., .env files)
						`|(?-i:(?:[A-Z_]+=\n[A-Z_]+=|[a-z_]+=\n[a-z_]+=)(?:\n|\z))` +
						`|(?-i:(?:[A-Z.]+=\n[A-Z.]+=|[a-z.]+=\n[a-z.]+=)(?:\n|\z))` +
						`)`).String(),
				},
				StopWords: append(DefaultStopWords,
					"6fe4476ee5a1832882e326b506d14126", // https://github.com/yarnpkg/berry/issues/6201
				),
			},
			{
				RegexTarget: "line",
				Regexes: []string{
					// Docker build secrets (https://docs.docker.com/build/building/secrets/#using-build-secrets).
					regexp.MustCompile(`--mount=type=secret,`).String(),
					//  https://github.com/gitleaks/gitleaks/issues/1800
					regexp.MustCompile(`import[ \t]+{[ \t\w,]+}[ \t]+from[ \t]+['"][^'"]+['"]`).String(),
				},
			},
			{
				MatchCondition: "AND",
				RegexTarget:    "line",
				Regexes: []string{
					regexp.MustCompile(`LICENSE[^=]*=\s*"[^"]+`).String(),
					regexp.MustCompile(`LIC_FILES_CHKSUM[^=]*=\s*"[^"]+`).String(),
					regexp.MustCompile(`SRC[^=]*=\s*"[a-zA-Z0-9]+`).String(),
				},
				Paths: []string{
					regexp.MustCompile(`\.bb$`).String(),
					regexp.MustCompile(`\.bbappend$`).String(),
					regexp.MustCompile(`\.bbclass$`).String(),
					regexp.MustCompile(`\.inc$`).String(),
				},
			},
		},
		Severity:      "High",
		Tags:          []string{TagApiKey},
		Category:      CategoryGeneralOrUnknown,
		ScoreRuleType: 4,
	}
}
