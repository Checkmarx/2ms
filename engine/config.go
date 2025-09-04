package engine

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

// Taken from gitleaks config
// https://github.com/gitleaks/gitleaks/blob/6c52f878cc48a513849900a9aa6f9d68e1c2dbdd/config/gitleaks.toml#L15-L26
var cfg = config.Config{
	Allowlists: []*config.Allowlist{
		{
			Paths: []*regexp.Regexp{
				regexp.MustCompile(`gitleaks\.toml`),
				regexp.MustCompile(`(?i)\.(?:bmp|gif|jpe?g|png|svg|tiff?)$`),
				regexp.MustCompile(`(?i)\.(?:eot|[ot]tf|woff2?)$`),
				regexp.MustCompile(`(?i)\.(?:docx?|xlsx?|pdf|bin|socket|vsidx|v2|suo|wsuo|.dll|pdb|exe|gltf)$`),
				regexp.MustCompile(`go\.(?:mod|sum|work(?:\.sum)?)$`),
				regexp.MustCompile(`(?:^|/)vendor/modules\.txt$`),
				regexp.MustCompile(`(?:^|/)vendor/(?:github\.com|golang\.org/x|google\.golang\.org|gopkg\.in|istio\.io|k8s\.io|sigs\.k8s\.io)(?:/.*)?$`), //nolint:lll
				regexp.MustCompile(`(?:^|/)gradlew(?:\.bat)?$`),
				regexp.MustCompile(`(?:^|/)gradle\.lockfile$`),
				regexp.MustCompile(`(?:^|/)mvnw(?:\.cmd)?$`),
				regexp.MustCompile(`(?:^|/)\.mvn/wrapper/MavenWrapperDownloader\.java$`),
				regexp.MustCompile(`(?:^|/)node_modules(?:/.*)?$`),
				regexp.MustCompile(`(?:^|/)(?:deno\.lock|npm-shrinkwrap\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$`),
				regexp.MustCompile(`(?:^|/)bower_components(?:/.*)?$`),
				regexp.MustCompile(`(?:^|/)(?:angular|bootstrap|jquery(?:-?ui)?|plotly|swagger-?ui)[a-zA-Z0-9.-]*(?:\.min)?\.js(?:\.map)?$`),
				regexp.MustCompile(`(?:^|/)javascript\.json$`),
				regexp.MustCompile(`(?:^|/)(?:Pipfile|poetry)\.lock$`),
				regexp.MustCompile(`(?i)(?:^|/)(?:v?env|virtualenv)/lib(?:64)?(?:/.*)?$`),
				regexp.MustCompile(`(?i)(?:^|/)(?:lib(?:64)?/python[23](?:\.\d{1,2})+|python/[23](?:\.\d{1,2})+/lib(?:64)?)(?:/.*)?$`),
				regexp.MustCompile(`(?i)(?:^|/)[a-z0-9_.]+-[0-9.]+\.dist-info(?:/.+)?$`),
				regexp.MustCompile(`(?:^|/)vendor/(?:bundle|ruby)(?:/.*?)?$`),
				regexp.MustCompile(`\.gem$`),
				regexp.MustCompile(`verification-metadata\.xml`),
				regexp.MustCompile(`Database.refactorlog`),
				regexp.MustCompile(`(?:^|/)\.git$`),
			},
		},
	},
}
