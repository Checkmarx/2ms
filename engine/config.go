package engine

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

// Taken from gitleaks config
// https://github.com/gitleaks/gitleaks/blob/6c52f878cc48a513849900a9aa6f9d68e1c2dbdd/config/gitleaks.toml#L15-L26
var cfg = config.Config{
	Allowlist: config.Allowlist{
		Paths: []*regexp.Regexp{
			regexp.MustCompile(`gitleaks.toml`),
			regexp.MustCompile(`(.*?)(jpg|gif|doc|docx|zip|xls|pdf|bin|svg|socket|vsidx|v2|suo|wsuo|.dll|pdb|exe)$`),
			regexp.MustCompile(`(go.mod|go.sum)$`),
			regexp.MustCompile(`gradle.lockfile`),
			regexp.MustCompile(`node_modules`),
			regexp.MustCompile(`package-lock.json`),
			regexp.MustCompile(`yarn.lock`),
			regexp.MustCompile(`pnpm-lock.yaml`),
			regexp.MustCompile(`Database.refactorlog`),
			regexp.MustCompile(`vendor`),
		},
	},
}
