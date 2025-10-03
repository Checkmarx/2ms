package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

// OnePasswordSecretKey Reference:
// - https://1passwordstatic.com/files/security/1password-white-paper.pdf
func OldOnePasswordSecretKey() *config.Rule {
	// 1Password secret keys include several hyphens but these are only for readability
	// and are stripped during 1Password login. This means that the following are technically
	// the same valid key:
	//   - A3ASWWYB798JRYLJVD423DC286TVMH43EB
	//   - A-3-A-S-W-W-Y-B-7-9-8-J-R-Y-L-J-V-D-4-2-3-D-C-2-8-6-T-V-M-H-4-3-E-B
	// But in practice, when these keys are added to a vault, exported in an emergency kit, or
	// copied, they have hyphens that follow one of two patterns I can find:
	//   - A3-ASWWYB-798JRY-LJVD4-23DC2-86TVM-H43EB (every key I've generated has this pattern)
	//   - A3-ASWWYB-798JRYLJVD4-23DC2-86TVM-H43EB  (the whitepaper includes this example, which could just be a typo)
	// To avoid a complicated regex that checks for every possible situation it's probably best
	// to scan for the these two patterns.
	return &config.Rule{
		Description: "Uncovered a possible 1Password secret key, potentially compromising access to secrets in vaults.",
		RuleID:      "1password-secret-key",
		Regex:       regexp.MustCompile(`\bA3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b`), //nolint:lll
		Entropy:     3.8,
		Keywords:    []string{"A3-"},
	}
}
