package engine

import (
	"bufio"
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"text/tabwriter"

	"github.com/checkmarx/2ms/v4/engine/chunk"
	"github.com/checkmarx/2ms/v4/engine/detect"
	"github.com/checkmarx/2ms/v4/engine/extra"
	"github.com/checkmarx/2ms/v4/engine/linecontent"
	"github.com/checkmarx/2ms/v4/engine/rules"
	"github.com/checkmarx/2ms/v4/engine/rules/ruledefine"
	"github.com/checkmarx/2ms/v4/engine/score"
	"github.com/checkmarx/2ms/v4/engine/semaphore"
	"github.com/checkmarx/2ms/v4/engine/validation"
	"github.com/checkmarx/2ms/v4/internal/resources"
	"github.com/checkmarx/2ms/v4/internal/workerpool"
	"github.com/checkmarx/2ms/v4/lib/reporting"
	"github.com/checkmarx/2ms/v4/lib/secrets"
	"github.com/checkmarx/2ms/v4/plugins"
	"github.com/rs/zerolog/log"
	"github.com/sourcegraph/conc"
	"github.com/spf13/cobra"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/report"
)

var (
	defaultDetectorWorkerPoolSize = runtime.GOMAXPROCS(0) * 2 // 2x the number of CPUs based on benchmark

	mu sync.Mutex

	ErrNoRulesSelected          = fmt.Errorf("no rules were selected")
	ErrFailedToCompileRegexRule = fmt.Errorf("failed to compile regex rule")
	errMissingRuleID            = fmt.Errorf("missing ruleID")
	errMissingRegex             = fmt.Errorf("missing regex")
	errInvalidRegex             = fmt.Errorf("invalid regex")
	errInvalidSeverity          = fmt.Errorf("invalid severity")
	errInvalidCategory          = fmt.Errorf("invalid category")
	errInvalidRuleType          = fmt.Errorf("invalid rule type")
)

type DetectorConfig struct {
	SelectedRules         []*ruledefine.Rule
	CustomRegexPatterns   []string
	AdditionalIgnoreRules []string
	MaxTargetMegabytes    int
	MaxFindings               int                // Total findings limit across entire scan
	MaxRuleMatchesPerFragment int                // Regex matches limit per rule per fragment
	MaxSecretSize             int                // Maximum secret size in bytes (0 = no limit)
}

type Engine struct {
	rules map[string]*ruledefine.Rule

	detector       *detect.Detector
	detectorConfig DetectorConfig

	validator    validation.Validator
	scorer       IScorer
	semaphore    semaphore.ISemaphore
	chunk        chunk.IChunk
	detectorPool workerpool.Pool

	ignoredIds    *[]string
	allowedValues *[]string

	pluginChannels plugins.PluginChannels

	secretsChan                    chan *secrets.Secret
	secretsExtrasChan              chan *secrets.Secret
	validationChan                 chan *secrets.Secret
	cvssScoreWithoutValidationChan chan *secrets.Secret

	Report reporting.IReport

	ScanConfig resources.ScanConfig

	wg conc.WaitGroup

	// Atomic counter to track findings across concurrent workers immediately
	findingsCounter atomic.Uint64
}

type IEngine interface {
	DetectFragment(item plugins.ISourceItem, secretsChannel chan *secrets.Secret, pluginName string) error
	DetectFile(ctx context.Context, item plugins.ISourceItem, secretsChannel chan *secrets.Secret) error

	GetReport() reporting.IReport

	Scan(pluginName string)
	Wait()

	GetPluginChannels() plugins.PluginChannels
	SetPluginChannels(pluginChannels plugins.PluginChannels)

	GetErrorsCh() chan error

	Shutdown() error
}

type IScorer interface {
	AssignScoreAndSeverity(secret *secrets.Secret)
	GetRulesBaseRiskScore(ruleId string) float64
	GetKeywords() map[string]struct{}
	GetRulesToBeApplied() map[string]config.Rule
}

type ctxKey string

const (
	customRegexRuleIdFormat = "custom-regex-%d"
	totalLinesKey           ctxKey = "totalLines"
	linesInChunkKey         ctxKey = "linesInChunk"
)

type EngineConfig struct {
	SelectedList []string
	IgnoreList   []string
	SpecialList  []string

	MaxTargetMegabytes        int
	MaxFindings               int // Total findings limit across entire scan
	MaxRuleMatchesPerFragment int // Regex matches limit per rule per fragment
	MaxSecretSize             int // Maximum secret size in bytes (0 = no limit)

	IgnoredIds    []string
	AllowedValues []string

	DetectorWorkerPoolSize int

	CustomRegexPatterns   []string
	AdditionalIgnoreRules []string

	CustomRules []*ruledefine.Rule

	ScanConfig resources.ScanConfig
}

type EngineOption func(*Engine)

func WithPluginChannels(pluginChannels plugins.PluginChannels) EngineOption {
	return func(e *Engine) {
		e.pluginChannels = pluginChannels
	}
}

func Init(engineConfig *EngineConfig, opts ...EngineOption) (IEngine, error) {
	return initEngine(engineConfig, opts...)
}

func initEngine(engineConfig *EngineConfig, opts ...EngineOption) (*Engine, error) {
	err := CheckRulesRequiredFields(engineConfig.CustomRules)
	if err != nil {
		return nil, fmt.Errorf("failed to load custom rules: %w", err)
	}

	selectedRules := rules.FilterRules(engineConfig.SelectedList,
		engineConfig.IgnoreList, engineConfig.SpecialList, engineConfig.CustomRules)

	// Apply additional ignore rules to get final rules
	finalRules := selectedRules
	if len(engineConfig.AdditionalIgnoreRules) > 0 {
		finalRules = filterIgnoredRules(selectedRules, engineConfig.AdditionalIgnoreRules)
	}

	if len(finalRules) == 0 {
		return nil, ErrNoRulesSelected
	}

	scorer := score.NewScorer(finalRules, engineConfig.ScanConfig.WithValidation)

	fileWalkerWorkerPoolSize := defaultDetectorWorkerPoolSize
	if engineConfig.DetectorWorkerPoolSize > 0 {
		fileWalkerWorkerPoolSize = engineConfig.DetectorWorkerPoolSize
	}

	engineRules := make(map[string]*ruledefine.Rule)
	for _, rule := range finalRules {
		engineRules[rule.RuleID] = rule
	}

	engine := &Engine{
		detectorConfig: DetectorConfig{
			SelectedRules:             finalRules,
			CustomRegexPatterns:       engineConfig.CustomRegexPatterns,
			AdditionalIgnoreRules:     engineConfig.AdditionalIgnoreRules,
			MaxTargetMegabytes:        engineConfig.MaxTargetMegabytes,
			MaxFindings:               engineConfig.MaxFindings,
			MaxRuleMatchesPerFragment: engineConfig.MaxRuleMatchesPerFragment,
			MaxSecretSize:             engineConfig.MaxSecretSize,
		},

		validator:    *validation.NewValidator(),
		scorer:       scorer,
		semaphore:    semaphore.NewSemaphore(),
		chunk:        chunk.New(),
		detectorPool: workerpool.New("detector", workerpool.WithWorkers(fileWalkerWorkerPoolSize)),

		ignoredIds:    &engineConfig.IgnoredIds,
		allowedValues: &engineConfig.AllowedValues,

		ScanConfig: engineConfig.ScanConfig,

		secretsChan:                    make(chan *secrets.Secret, runtime.GOMAXPROCS(0)),
		secretsExtrasChan:              make(chan *secrets.Secret, runtime.GOMAXPROCS(0)),
		validationChan:                 make(chan *secrets.Secret, runtime.GOMAXPROCS(0)),
		cvssScoreWithoutValidationChan: make(chan *secrets.Secret, runtime.GOMAXPROCS(0)),

		pluginChannels: plugins.NewChannels(),
		Report:         reporting.New(),

		rules: engineRules,
	}

	for _, opt := range opts {
		opt(engine)
	}

	// Initialize detector with complete configuration
	cfg := newConfig()
	cfg.Rules = scorer.GetRulesToBeApplied()
	cfg.Keywords = scorer.GetKeywords()

	// Add custom regex rules if any
	if len(engineConfig.CustomRegexPatterns) > 0 {
		log.Debug().Strs("custom_regex_patterns", engineConfig.CustomRegexPatterns).Msg("Creating custom regex rules")
		customRules, err := createCustomRegexRules(engineConfig.CustomRegexPatterns)
		if err != nil {
			return nil, fmt.Errorf("failed to create custom regex rules: %w", err)
		}
		for ruleID, customRule := range customRules {
			log.Debug().Str("rule_id", ruleID).Msg("Adding custom regex rule")
			cfg.Rules[ruleID] = *ruledefine.TwomsToGitleaksRule(customRule)
			engine.rules[ruleID] = customRule
		}
	}

	// Create detector with final config
	detector := detect.NewDetector(*cfg)
	detector.MaxTargetMegaBytes = engineConfig.MaxTargetMegabytes
	detector.MaxRuleMatchesPerFragment = engineConfig.MaxRuleMatchesPerFragment
	detector.MaxSecretSize = engineConfig.MaxSecretSize
	engine.detector = detector

	return engine, nil
}

// DetectFragment detects secrets in the given fragment
func (e *Engine) DetectFragment(item plugins.ISourceItem, secretsChannel chan *secrets.Secret, pluginName string) error {
	fragment := detect.Fragment{ //nolint:staticcheck // TODO: detect.Fragment is deprecated
		Raw:      *item.GetContent(),
		FilePath: item.GetSource(),
	}

	return e.detectSecrets(context.Background(), item, &fragment, secretsChannel, pluginName)
}

// DetectFile reads the given file and detects secrets in it
func (e *Engine) DetectFile(ctx context.Context, item plugins.ISourceItem, secretsChannel chan *secrets.Secret) error {
	fi, err := os.Stat(item.GetSource())
	if err != nil {
		return fmt.Errorf("failed to stat %q: %w", item.GetSource(), err)
	}

	fileSize := fi.Size()
	if e.isFileSizeExceedingLimit(fileSize) {
		log.Debug().Int64("size", fileSize/1000000).Msg("Skipping file: exceeds --max-target-megabytes")
		return nil
	}

	// Check if file size exceeds the file threshold, if so, use chu'king, if not, read the whole file
	if fileSize > e.chunk.GetFileThreshold() {
		// ChunkSize * 2             ->  raw read buffer + bufio.Reader's internal slice
		// ChunkSize * 2             ->  raw read buffer + bufio.Reader's internal slice
		// + (ChunkSize+MaxPeekSize) ->  peekBuf backing slice
		// + (ChunkSize+MaxPeekSize) ->  chunkStr copy
		weight := int64(e.chunk.GetSize()*4 + e.chunk.GetMaxPeekSize()*2)
		err = e.semaphore.AcquireMemoryWeight(ctx, weight)
		if err != nil {
			return fmt.Errorf("failed to acquire memory: %w", err)
		}
		defer e.semaphore.ReleaseMemoryWeight(weight)

		return e.detectChunks(ctx, item, secretsChannel)
	}
	// fileSize * 2 -> data file bytes and its conversion to string
	weight := fileSize * 2
	err = e.semaphore.AcquireMemoryWeight(ctx, weight)
	if err != nil {
		return fmt.Errorf("failed to acquire memory: %w", err)
	}
	defer e.semaphore.ReleaseMemoryWeight(weight)

	data, err := os.ReadFile(item.GetSource())
	if err != nil {
		return fmt.Errorf("read small file %q: %w", item.GetSource(), err)
	}
	fragment := detect.Fragment{ //nolint:staticcheck // TODO: detect.Fragment is deprecated
		Raw:      string(data),
		FilePath: item.GetSource(),
	}

	return e.detectSecrets(ctx, item, &fragment, secretsChannel, "filesystem")
}

// detectChunks reads the given file in chunks and detects secrets in each chunk
func (e *Engine) detectChunks(ctx context.Context, item plugins.ISourceItem, secretsChannel chan *secrets.Secret) error {
	f, err := os.Open(item.GetSource())
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", item.GetSource(), err)
	}
	defer func() {
		_ = f.Close()
	}()

	reader := bufio.NewReaderSize(f, e.chunk.GetSize()+e.chunk.GetMaxPeekSize())
	totalLines := 0

	// Read the file in chunks until EOF
	for {
		chunkStr, err := e.chunk.ReadChunk(reader, totalLines)
		if err != nil {
			if err.Error() == "skipping file: unsupported file type" {
				log.Debug().Msgf("Skipping file %s: unsupported file type", item.GetSource())
				return nil
			}
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("failed to read file %s: %w", item.GetSource(), err)
		}
		// Count the number of newlines in this chunk
		linesInChunk := strings.Count(chunkStr, "\n")
		totalLines += linesInChunk

		// Detect secrets in the chunk
		fragment := detect.Fragment{ //nolint:staticcheck // TODO: detect.Fragment is deprecated
			Raw:      chunkStr,
			FilePath: item.GetSource(),
		}
		ctx = context.WithValue(ctx, totalLinesKey, totalLines)
		ctx = context.WithValue(ctx, linesInChunkKey, linesInChunk)
		if detectErr := e.detectSecrets(ctx, item, &fragment, secretsChannel, "filesystem"); detectErr != nil {
			return fmt.Errorf("failed to detect secrets: %w", detectErr)
		}
	}
}

// detectSecrets detects secrets and sends them to the secrets channel
func (e *Engine) detectSecrets(
	ctx context.Context,
	item plugins.ISourceItem,
	fragment *detect.Fragment, //nolint:staticcheck // TODO: detect.Fragment is deprecated
	secrets chan *secrets.Secret,
	pluginName string,
) error {
	if e.detectorConfig.MaxFindings > 0 && e.findingsCounter.Load() >= uint64(e.detectorConfig.MaxFindings) {
		return nil
	}

	values := e.detector.Detect(*fragment)

	// Filter generic secrets if a better finding exists
	filteredValues := filterGenericDuplicateFindings(values)

	for _, value := range filteredValues { //nolint:gocritic // rangeValCopy: value is used immediately
		secret, buildErr := buildSecret(ctx, item, value, pluginName)
		if buildErr != nil {
			return fmt.Errorf("failed to build secret: %w", buildErr)
		}
		if !isSecretIgnored(secret, e.ignoredIds, e.allowedValues, value.Line, value.Match, pluginName) {
			if e.detectorConfig.MaxFindings > 0 {
				newCount := e.findingsCounter.Add(1)
				if newCount > uint64(e.detectorConfig.MaxFindings) {
					log.Warn().
						Int("max_findings", e.detectorConfig.MaxFindings).
						Msg("Maximum findings limit reached. Scan will stop early and report results up to this limit.")
					break
				}
			}
			secrets <- secret
		} else {
			log.Debug().Msgf("Secret %s was ignored", secret.ID)
		}
	}
	return nil
}

// isFileSizeExceedingLimit checks if the file size exceeds the max target megabytes limit
func (e *Engine) isFileSizeExceedingLimit(fileSize int64) bool {
	if e.detector.MaxTargetMegaBytes > 0 {
		rawLength := fileSize / 1000000 // convert to MB
		return rawLength > int64(e.detector.MaxTargetMegaBytes)
	}
	return false
}

// createCustomRegexRules creates a map of custom regex rules from the provided patterns
func createCustomRegexRules(patterns []string) (map[string]*ruledefine.Rule, error) {
	customRules := make(map[string]*ruledefine.Rule)
	for idx, pattern := range patterns {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrFailedToCompileRegexRule, pattern)
		}
		ruleID := fmt.Sprintf(customRegexRuleIdFormat, idx+1)
		rule := ruledefine.Rule{
			Description: "Custom Regex Rule From User",
			RuleID:      ruleID,
			RuleName:    ruleID,
			Regex:       regex.String(),
			Keywords:    []string{},
		}
		customRules[rule.RuleID] = &rule
	}
	return customRules, nil
}

// filterIgnoredRules filters out rules that should be ignored
func filterIgnoredRules(allRules []*ruledefine.Rule, ignoreList []string) []*ruledefine.Rule {
	if len(ignoreList) == 0 {
		return allRules
	}

	filtered := make([]*ruledefine.Rule, 0, len(allRules))
	for _, rule := range allRules {
		shouldIgnore := false

		// Check if this rule should be ignored (by ID or tag)
		for _, ignoreItem := range ignoreList {
			if strings.EqualFold(strings.ToLower(rule.RuleName), strings.ToLower(ignoreItem)) {
				shouldIgnore = true
				break
			}
			// Check tags
			for _, tag := range rule.Tags {
				if strings.EqualFold(tag, ignoreItem) {
					shouldIgnore = true
					break
				}
			}
			if shouldIgnore {
				break
			}
		}

		if !shouldIgnore {
			filtered = append(filtered, rule)
		}
	}

	return filtered
}

func (e *Engine) registerForValidation(secret *secrets.Secret) {
	disableValidation := e.rules[secret.RuleID].DisableValidation
	e.validator.RegisterForValidation(secret, disableValidation)
}

func (e *Engine) GetDetectorWorkerPool() workerpool.Pool {
	return e.detectorPool
}

func (e *Engine) Shutdown() error {
	mu.Lock()
	defer mu.Unlock()

	if e.detectorPool != nil {
		return e.detectorPool.Stop()
	}

	return nil
}

func GetRulesCommand(engineConfig *EngineConfig) *cobra.Command {
	canValidateDisplay := map[bool]string{
		true:  "V",
		false: "",
	}

	return &cobra.Command{
		Use:   "rules",
		Short: "List all rules",
		Long:  `List all rules`,
		RunE: func(cmd *cobra.Command, args []string) error {
			filteredRules := rules.FilterRules(engineConfig.SelectedList,
				engineConfig.IgnoreList, engineConfig.SpecialList, engineConfig.CustomRules)

			tab := tabwriter.NewWriter(os.Stdout, 1, 2, 2, ' ', 0)

			fmt.Fprintln(tab, "Name\tDescription\tTags\tValidity Check")
			fmt.Fprintln(tab, "----\t----\t----\t----")
			for _, rule := range filteredRules {
				fmt.Fprintf(
					tab,
					"%s\t%s\t%s\t%s\n",
					rule.RuleName,
					rule.Description,
					strings.Join(rule.Tags, ","),
					canValidateDisplay[validation.IsCanValidateRule(rule.RuleID)],
				)
			}
			if err := tab.Flush(); err != nil {
				return err
			}

			return nil
		},
	}
}

// buildSecret creates a secret object from the given source item and finding
func buildSecret(
	ctx context.Context,
	item plugins.ISourceItem,
	value report.Finding, //nolint:gocritic // hugeParam: value is heavy but needed
	pluginName string,
) (*secrets.Secret, error) {
	gitInfo := item.GetGitInfo()
	findingID, err := getFindingId(item, &value)
	if err != nil {
		return nil, fmt.Errorf("failed to get finding ID: %w", err)
	}

	startLine, endLine, err := getStartAndEndLines(ctx, pluginName, gitInfo, value)
	if err != nil {
		return nil, fmt.Errorf("failed to get start and end lines for source %s: %w", item.GetSource(), err)
	}

	hasNewline := strings.HasPrefix(value.Line, "\n")

	if hasNewline {
		value.Line = strings.TrimPrefix(value.Line, "\n")
	}
	value.Line = strings.ReplaceAll(value.Line, "\r", "")

	lineContent, err := linecontent.GetLineContent(value.Line, value.Secret)
	if err != nil {
		return nil, fmt.Errorf("failed to get line content for source %s: %w", item.GetSource(), err)
	}

	adjustedStartColumn := value.StartColumn
	adjustedEndColumn := value.EndColumn
	if hasNewline {
		adjustedStartColumn--
		adjustedEndColumn--
	}

	secret := &secrets.Secret{
		ID:              findingID,
		Source:          item.GetSource(),
		RuleID:          value.RuleID,
		StartLine:       startLine,
		StartColumn:     adjustedStartColumn,
		EndLine:         endLine,
		EndColumn:       adjustedEndColumn,
		Value:           value.Secret,
		LineContent:     lineContent,
		RuleDescription: value.Description,
	}

	if pluginName == "confluence" {
		if pageID, ok := plugins.ParseConfluenceItemID(item.GetID()); ok {
			if secret.ExtraDetails == nil {
				secret.ExtraDetails = make(map[string]interface{})
			}
			secret.ExtraDetails["confluence.pageId"] = pageID
		}
	}
	return secret, nil
}

func getFindingId(item plugins.ISourceItem, finding *report.Finding) (string, error) {
	// Context includes only non-sensitive metadata
	context := fmt.Sprintf("finding:%s:%s", item.GetID(), finding.RuleID)

	// Use secret hash as input key material
	// to avoid errors in FIPS 140-only mode
	// which requires the use of keys longer than 112 bits
	secretHash := sha256.Sum256([]byte(finding.Secret))

	// Use the newer HKDF API - Key function does both extract and expand
	id, err := hkdf.Key(sha256.New, secretHash[:], nil, context, 20)
	if err != nil {
		return "", fmt.Errorf("HKDF derivation failed: %w", err)
	}

	return hex.EncodeToString(id), nil
}

func getStartAndEndLines(
	ctx context.Context,
	pluginName string,
	gitInfo *plugins.GitInfo,
	value report.Finding, //nolint:gocritic // hugeParam: value is heavy but needed
) (int, int, error) {
	var startLine, endLine int
	var err error

	switch pluginName {
	case "filesystem":
		totalLines, totalOK := ctx.Value(totalLinesKey).(int)
		chunkLines, chunkOK := ctx.Value(linesInChunkKey).(int)

		offset := 1
		if totalOK && chunkOK {
			offset = (totalLines - chunkLines) + 1
		}

		startLine = value.StartLine + offset
		endLine = value.EndLine + offset
	case "git":
		startLine, endLine, err = plugins.GetGitStartAndEndLine(gitInfo, value.StartLine, value.EndLine)
		if err != nil {
			return 0, 0, err
		}
	default:
		startLine = value.StartLine
		endLine = value.EndLine
	}

	return startLine, endLine, nil
}

func isSecretIgnored(secret *secrets.Secret, ignoredIds, allowedValues *[]string, secretLine, secretMatch, pluginName string) bool {
	for _, allowedValue := range *allowedValues {
		if secret.Value == allowedValue {
			return true
		}
	}
	if pluginName == "confluence" && isSecretFromConfluenceResourceIdentifier(secret.RuleID, secretLine, secretMatch) {
		return true
	}
	return slices.Contains(*ignoredIds, secret.ID)
}

func (e *Engine) processItems(pluginName string) {
	e.consumeItems(pluginName)

	// After all items are processed (items channel closed),
	// close the queue to signal no more work will be submitted
	e.GetDetectorWorkerPool().CloseQueue()

	// Wait for all submitted tasks to complete
	e.GetDetectorWorkerPool().Wait()

	close(e.secretsChan)
}

// consumeItems uses the engine's worker pool
func (e *Engine) consumeItems(pluginName string) {
	ctx := context.Background()
	pool := e.GetDetectorWorkerPool()

	// Process items until the channel is closed
	for item := range e.pluginChannels.GetItemsCh() {
		e.Report.IncTotalItemsScanned(1)

		// Create task based on plugin type
		var task workerpool.Task
		switch pluginName {
		case "filesystem":
			task = func(context.Context) error {
				return e.DetectFile(ctx, item, e.secretsChan)
			}
		default:
			task = func(context.Context) error {
				return e.DetectFragment(item, e.secretsChan, pluginName)
			}
		}

		if err := pool.Submit(task); err != nil {
			if err == workerpool.ErrQueueClosed {
				log.Warn().Msg("Queue already closed, cannot submit task")
				break
			}
			log.Error().Err(err).Msg("error submitting task")
			e.pluginChannels.GetErrorsCh() <- err
		}
		log.Debug().Msg("submitted task")
	}
	// Items channel is now closed, no more items will be received
	log.Debug().Msg("Items channel closed, no more items to process")
}

func (e *Engine) processSecrets() {
	if e.ScanConfig.WithValidation {
		e.processSecretsWithValidation()
	} else {
		e.processSecretsWithoutValidation()
	}
}

func (e *Engine) processSecretsWithoutValidation() {
	for secret := range e.secretsChan {
		e.Report.IncTotalSecretsFound(1)
		e.secretsExtrasChan <- secret
		e.cvssScoreWithoutValidationChan <- secret
		results := e.Report.GetResults()
		results[secret.ID] = append(results[secret.ID], secret)
	}
	close(e.secretsExtrasChan)
	close(e.cvssScoreWithoutValidationChan)
}

func (e *Engine) processSecretsWithValidation() {
	for secret := range e.secretsChan {
		e.Report.IncTotalSecretsFound(1)
		e.secretsExtrasChan <- secret
		e.validationChan <- secret
		results := e.Report.GetResults()
		results[secret.ID] = append(results[secret.ID], secret)
	}
	close(e.secretsExtrasChan)
	close(e.validationChan)
}

func (e *Engine) processSecretsExtras() {
	for secret := range e.secretsExtrasChan {
		e.addExtrasToSecret(secret)
	}
}

func (e *Engine) processEvaluationWithValidation() {
	for secret := range e.validationChan {
		e.registerForValidation(secret)
		e.scorer.AssignScoreAndSeverity(secret)
	}
	e.validator.Validate()
}

func (e *Engine) processEvaluationWithoutValidation() {
	for secret := range e.cvssScoreWithoutValidationChan {
		e.scorer.AssignScoreAndSeverity(secret)
	}
}

// processSecretsEvaluation evaluates the secret's validationStatus, Severity and CVSS score
func (e *Engine) processSecretsEvaluation() {
	if e.ScanConfig.WithValidation {
		e.processEvaluationWithValidation()
	} else {
		e.processEvaluationWithoutValidation()
	}
}

func (e *Engine) addExtrasToSecret(secret *secrets.Secret) {
	// add general extra data
	extra.Mtxs.Lock(secret.ID)
	secret.RuleName = e.rules[secret.RuleID].RuleName
	secret.RuleCategory = string(e.rules[secret.RuleID].Category)
	extra.Mtxs.Unlock(secret.ID)

	// add rule specific extra data
	if addExtra, ok := extra.RuleIDToFunction[secret.RuleID]; ok {
		extraData := addExtra(secret)
		if extraData != nil && extraData != "" {
			extra.UpdateExtraField(secret, "secretDetails", extraData)
		}
	}
}

func (e *Engine) GetReport() reporting.IReport {
	return e.Report
}

func (e *Engine) GetPluginChannels() plugins.PluginChannels {
	return e.pluginChannels
}

func (e *Engine) SetPluginChannels(pluginChannels plugins.PluginChannels) {
	e.pluginChannels = pluginChannels
}

func (e *Engine) GetErrorsCh() chan error {
	return e.pluginChannels.GetErrorsCh()
}

func (e *Engine) GetSecretsExtrasCh() chan *secrets.Secret {
	return e.secretsExtrasChan
}

func (e *Engine) GetValidationCh() chan *secrets.Secret {
	return e.validationChan
}

func (e *Engine) GetCvssScoreWithoutValidationCh() chan *secrets.Secret {
	return e.cvssScoreWithoutValidationChan
}

func (e *Engine) Scan(pluginName string) {
	e.wg.Go(func() {
		e.processItems(pluginName)
	})
	e.wg.Go(func() {
		e.processSecrets()
	})
	e.wg.Go(func() {
		e.processSecretsEvaluation()
	})
	e.wg.Go(func() {
		e.processSecretsExtras()
	})
}

func (e *Engine) Wait() {
	e.wg.Wait()
}

func filterGenericDuplicateFindings(findings []report.Finding) []report.Finding {
	var retFindings []report.Finding
	for i := range findings {
		f := &findings[i]
		include := true
		if strings.Contains(strings.ToLower(f.RuleID), "01ab7659-d25a-4a1c-9f98-dee9d0cf2e70") { // generic rule ID
			for j := range findings {
				fPrime := &findings[j]
				if f.StartLine == fPrime.StartLine &&
					f.Commit == fPrime.Commit &&
					f.RuleID != fPrime.RuleID &&
					strings.Contains(fPrime.Secret, f.Secret) &&
					!strings.Contains(strings.ToLower(fPrime.RuleID), "01ab7659-d25a-4a1c-9f98-dee9d0cf2e70") {
					genericMatch := strings.ReplaceAll(f.Match, f.Secret, "REDACTED")
					betterMatch := strings.ReplaceAll(fPrime.Match, fPrime.Secret, "REDACTED")
					logging.Trace().Msgf("skipping %s finding (%s), %s rule takes precedence (%s)", f.RuleID, genericMatch, fPrime.RuleID, betterMatch)
					include = false
					break
				}
			}
		}

		if include {
			retFindings = append(retFindings, *f)
		}
	}
	return retFindings
}

// isSecretFromConfluenceResourceIdentifier reports whether a regex match found in a line
// actually belongs to Confluence Storage Format metadata (the `ri:` namespace) rather than
// real user content. This lets us ignore false-positives that cannot be suppressed via the
// generic-api-key rule allow-list.
func isSecretFromConfluenceResourceIdentifier(secretRuleID, secretLine, secretMatch string) bool {
	if secretRuleID != ruledefine.GenericCredential().RuleID || secretLine == "" || secretMatch == "" {
		return false
	}

	q := regexp.QuoteMeta(secretMatch)

	pat := `<[^>]*\sri:` + q + `[^>]*>`
	re := regexp.MustCompile(pat)
	return re.MatchString(secretLine)
}

// CheckRulesRequiredFields checks that required fields are present in the Rule.
// This is meant for user defined rules, default rules have more strict checks in unit tests
func CheckRulesRequiredFields(rulesToCheck []*ruledefine.Rule) error {
	var err error
	for i, rule := range rulesToCheck {
		if rule.RuleID == "" {
			err = errors.Join(err, buildCustomRuleError(i, rule, errMissingRuleID))
		}

		if rule.Regex == "" {
			err = errors.Join(err, buildCustomRuleError(i, rule, errMissingRegex))
		} else {
			if _, errRegex := regexp.Compile(rule.Regex); errRegex != nil {
				invalidRegexError := fmt.Errorf("%w: %v", errInvalidRegex, errRegex)
				err = errors.Join(err, buildCustomRuleError(i, rule, invalidRegexError))
			}
		}

		if rule.Severity != "" {
			if !slices.Contains(ruledefine.SeverityOrder, rule.Severity) {
				invalidSeverityError := fmt.Errorf("%w: %s not one of (%s)", errInvalidSeverity, rule.Severity, ruledefine.SeverityOrder)
				err = errors.Join(err, buildCustomRuleError(i, rule, invalidSeverityError))
			}
		}

		_, validCategory := score.CategoryScoreMap[rule.Category]
		if rule.Category != "" && !validCategory {
			invalidCategoryError := fmt.Errorf("%w: %s not an acceptable category of type RuleCategory",
				errInvalidCategory, rule.Category)
			err = errors.Join(err, buildCustomRuleError(i, rule, invalidCategoryError))
		}

		if rule.ScoreRuleType != 0 && rule.ScoreRuleType > score.RuleTypeMaxValue {
			invalidRuleTypeError := fmt.Errorf("%w: %d not an acceptable uint8 value, should be between 1 and 4",
				errInvalidRuleType, rule.ScoreRuleType)
			err = errors.Join(err, buildCustomRuleError(i, rule, invalidRuleTypeError))
		}
	}

	// Add a newline at start of error if it's not nil, for better presentation in output
	if err != nil {
		err = fmt.Errorf("\n%w", err)
	}

	return err
}

func buildCustomRuleError(ruleIndex int, rule *ruledefine.Rule, issue error) error {
	if rule.RuleID == "" {
		if rule.RuleName == "" {
			return fmt.Errorf("rule#%d: %w", ruleIndex, issue)
		}
		return fmt.Errorf("rule#%d;RuleName-%s: %w", ruleIndex, rule.RuleName, issue)
	}
	return fmt.Errorf("rule#%d;RuleID-%s: %w", ruleIndex, rule.RuleID, issue)
}
