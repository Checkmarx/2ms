package detect

import (
	"context"
	"regexp"
	"strings"
	"sync"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"github.com/fatih/semgroup"

	"github.com/rs/zerolog/log"
)

const (
	gitleaksAllowSignature = "gitleaks:allow"
	chunkSize              = 10 * 1_000 // 10kb
)

// Detector is the main detector struct
type Detector struct {
	// Config is the configuration for the detector
	Config config.Config

	// Redact is a flag to redact findings. This is exported
	// so users using gitleaks as a library can set this flag
	// without calling `detector.Start(cmd *cobra.Command)`
	Redact uint

	// verbose is a flag to print findings
	Verbose bool

	// files larger than this will be skipped
	MaxTargetMegaBytes int

	// followSymlinks is a flag to enable scanning symlink files
	FollowSymlinks bool

	// NoColor is a flag to disable color output
	NoColor bool

	// IgnoreGitleaksAllow is a flag to ignore gitleaks:allow comments.
	IgnoreGitleaksAllow bool

	// commitMap is used to keep track of commits that have been scanned.
	// This is only used for logging purposes and git scans.
	commitMap map[string]bool

	// findingMutex is to prevent concurrent access to the
	// findings slice when adding findings.
	findingMutex *sync.Mutex

	// findings is a slice of report.Findings. This is the result
	// of the detector's scan which can then be used to generate a
	// report.
	findings []report.Finding

	// prefilter is a ahocorasick struct used for doing efficient string
	// matching given a set of words (keywords from the rules in the config)
	prefilter ahocorasick.Trie

	// a list of known findings that should be ignored
	baseline []report.Finding

	// path to baseline
	baselinePath string

	// gitleaksIgnore
	gitleaksIgnore map[string]bool

	// Sema (https://github.com/fatih/semgroup) controls the concurrency
	Sema *semgroup.Group
}

// Fragment contains the data to be scanned
type Fragment struct {
	// Raw is the raw content of the fragment
	Raw string

	// FilePath is the path to the file if applicable
	FilePath    string
	SymlinkFile string

	// CommitSHA is the SHA of the commit if applicable
	CommitSHA string

	// newlineIndices is a list of indices of newlines in the raw content.
	// This is used to calculate the line location of a finding
	newlineIndices [][]int

	// keywords is a map of all the keywords contain within the contents
	// of this fragment
	keywords map[string]bool
}

// NewDetector creates a new detector with the given config
func NewDetector(cfg *config.Config) *Detector {
	return &Detector{
		commitMap:      make(map[string]bool),
		gitleaksIgnore: make(map[string]bool),
		findingMutex:   &sync.Mutex{},
		findings:       make([]report.Finding, 0),
		Config:         *cfg,
		prefilter:      *ahocorasick.NewTrieBuilder().AddStrings(cfg.Keywords).Build(),
		Sema:           semgroup.NewGroup(context.Background(), 40),
	}
}

// DetectBytes scans the given bytes and returns a list of findings
func (d *Detector) DetectBytes(content []byte) []report.Finding {
	return d.DetectString(string(content))
}

// DetectString scans the given string and returns a list of findings
func (d *Detector) DetectString(content string) []report.Finding {
	frag := &Fragment{
		Raw: content,
	}
	return d.Detect(frag)
}

// Detect scans the given fragment and returns a list of findings
// TODO: Refactor to remove iteration copies (gocritic)
func (d *Detector) Detect(fragment *Fragment) []report.Finding {
	var findings []report.Finding

	// initiate fragment keywords
	fragment.keywords = make(map[string]bool)

	// check if filepath is allowed
	if fragment.FilePath != "" && (d.Config.Allowlist.PathAllowed(fragment.FilePath) ||
		fragment.FilePath == d.Config.Path || (d.baselinePath != "" && fragment.FilePath == d.baselinePath)) {
		return findings
	}

	// add newline indices for location calculation in detectRule

	fragment.newlineIndices = regexp.MustCompile("\n|$").FindAllStringIndex(fragment.Raw, -1)

	// build keyword map for prefiltering rules
	normalizedRaw := strings.ToLower(fragment.Raw)
	matches := d.prefilter.MatchString(normalizedRaw)
	for _, m := range matches {
		fragment.keywords[normalizedRaw[m.Pos():int(m.Pos())+len(m.Match())]] = true
	}

	rulePtrs := make([]*config.Rule, 0, len(d.Config.Rules))
	for i := range d.Config.Rules {
		rule := d.Config.Rules[i]
		rulePtrs = append(rulePtrs, &rule)
	}
	for _, rulePtr := range rulePtrs {
		if len(rulePtr.Keywords) == 0 {
			findings = append(findings, d.detectRule(fragment, rulePtr)...)
			continue
		}
		fragmentContainsKeyword := false
		for _, k := range rulePtr.Keywords {
			if _, ok := fragment.keywords[strings.ToLower(k)]; ok {
				fragmentContainsKeyword = true
			}
		}
		if fragmentContainsKeyword {
			findings = append(findings, d.detectRule(fragment, rulePtr)...)
		}
	}
	return findings
}

// detectRule scans the given fragment for the given rule and returns a list of findings
func (d *Detector) detectRule(fragment *Fragment, rule *config.Rule) []report.Finding {
	var findings []report.Finding

	if d.shouldSkipRule(fragment, rule) {
		return findings
	}

	matchIndices := d.getMatchIndices(fragment, rule)
	for _, matchIndex := range matchIndices {
		finding, ok := d.buildFinding(fragment, rule, matchIndex)
		if !ok {
			continue
		}
		findings = append(findings, finding)
	}
	return findings
}

// shouldSkipRule centralizes early return checks for rule applicability
func (d *Detector) shouldSkipRule(fragment *Fragment, rule *config.Rule) bool {
	if rule.Allowlist.CommitAllowed(fragment.CommitSHA) ||
		rule.Allowlist.PathAllowed(fragment.FilePath) {
		return true
	}
	if rule.Path != nil && rule.Regex == nil {
		if rule.Path.MatchString(fragment.FilePath) {
			return true // handled as finding in buildFinding
		}
	} else if rule.Path != nil {
		if !rule.Path.MatchString(fragment.FilePath) {
			return true
		}
	}
	if rule.Regex == nil {
		return true
	}
	if d.MaxTargetMegaBytes > 0 {
		rawLength := len(fragment.Raw) / 1000000
		if rawLength > d.MaxTargetMegaBytes {
			log.Debug().Msgf("skipping file: %s scan due to size: %d", fragment.FilePath, rawLength)
			return true
		}
	}
	return false
}

// getMatchIndices centralizes the retrieval of match indices
func (d *Detector) getMatchIndices(fragment *Fragment, rule *config.Rule) [][]int {
	if rule.Regex == nil {
		return nil
	}
	return rule.Regex.FindAllStringIndex(fragment.Raw, -1)
}

// buildFinding centralizes the construction and filtering of findings
func (d *Detector) buildFinding(fragment *Fragment, rule *config.Rule, matchIndex []int) (report.Finding, bool) {
	secret := strings.Trim(fragment.Raw[matchIndex[0]:matchIndex[1]], "\n")
	loc := location(fragment, matchIndex)
	if matchIndex[1] > loc.endLineIndex {
		loc.endLineIndex = matchIndex[1]
	}
	finding := report.Finding{
		Description: rule.Description,
		File:        fragment.FilePath,
		SymlinkFile: fragment.SymlinkFile,
		RuleID:      rule.RuleID,
		StartLine:   loc.startLine,
		EndLine:     loc.endLine,
		StartColumn: loc.startColumn,
		EndColumn:   loc.endColumn,
		Secret:      secret,
		Match:       secret,
		Tags:        rule.Tags,
		Line:        fragment.Raw[loc.startLineIndex:loc.endLineIndex],
	}
	if strings.Contains(fragment.Raw[loc.startLineIndex:loc.endLineIndex],
		gitleaksAllowSignature) && !d.IgnoreGitleaksAllow {
		return finding, false
	}
	groups := rule.Regex.FindStringSubmatch(secret)
	if !extractSecretGroup(rule, groups, &secret, &finding) {
		return finding, false
	}
	if d.isFindingAllowlisted(rule, &finding) {
		return finding, false
	}
	if d.isFindingStopworded(rule, &finding) {
		return finding, false
	}
	if !d.isFindingEntropyValid(rule, &finding, secret) {
		return finding, false
	}
	return finding, true
}

// extractSecretGroup handles secret group extraction logic
func extractSecretGroup(rule *config.Rule, groups []string, secret *string, finding *report.Finding) bool {
	if rule.SecretGroup == 0 {
		if len(groups) == 2 {
			*secret = groups[1]
			finding.Secret = *secret
		}
	} else {
		if len(groups) <= rule.SecretGroup || len(groups) == 0 {
			return false
		}
		*secret = groups[rule.SecretGroup]
		finding.Secret = *secret
	}
	return true
}

// isFindingAllowlisted checks allowlist conditions for a finding
func (d *Detector) isFindingAllowlisted(rule *config.Rule, finding *report.Finding) bool {
	allowlistTarget := finding.Secret
	switch rule.Allowlist.RegexTarget {
	case "match":
		allowlistTarget = finding.Match
	case "line":
		allowlistTarget = finding.Line
	}
	globalAllowlistTarget := finding.Secret
	switch d.Config.Allowlist.RegexTarget {
	case "match":
		globalAllowlistTarget = finding.Match
	case "line":
		globalAllowlistTarget = finding.Line
	}
	return rule.Allowlist.RegexAllowed(allowlistTarget) ||
		d.Config.Allowlist.RegexAllowed(globalAllowlistTarget)
}

// isFindingStopworded checks stopword conditions for a finding
func (d *Detector) isFindingStopworded(rule *config.Rule, finding *report.Finding) bool {
	return rule.Allowlist.ContainsStopWord(finding.Secret) ||
		d.Config.Allowlist.ContainsStopWord(finding.Secret)
}

// isFindingEntropyValid checks entropy and generic rule digit conditions
func (d *Detector) isFindingEntropyValid(rule *config.Rule, finding *report.Finding, secret string) bool {
	entropy := shannonEntropy(finding.Secret)
	finding.Entropy = float32(entropy)
	if rule.Entropy != 0.0 {
		if entropy <= rule.Entropy {
			return false
		}
		if strings.HasPrefix(rule.RuleID, "generic") {
			if !containsDigit(secret) {
				return false
			}
		}
	}
	return true
}
