package rules

import (
	"strings"

	"github.com/zricethezav/gitleaks/v8/regexp"
)

func generateUniqueTokenRegex(secretRegex string, isCaseInsensitive bool) *regexp.Regexp {
	var sb strings.Builder
	if isCaseInsensitive {
		sb.WriteString(caseInsensitive)
	}
	sb.WriteString(secretPrefixUnique)
	sb.WriteString(secretRegex)
	sb.WriteString(secretSuffix)
	return regexp.MustCompile(sb.String())
}
