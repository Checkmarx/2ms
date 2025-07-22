package engine

import (
	"bufio"
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"strings"
	"text/tabwriter"

	"github.com/checkmarx/2ms/v4/engine/chunk"
	"github.com/checkmarx/2ms/v4/engine/linecontent"
	"github.com/checkmarx/2ms/v4/engine/rules"
	"github.com/checkmarx/2ms/v4/engine/score"
	"github.com/checkmarx/2ms/v4/engine/semaphore"
	"github.com/checkmarx/2ms/v4/engine/validation"
	"github.com/checkmarx/2ms/v4/lib/secrets"
	"github.com/checkmarx/2ms/v4/plugins"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

var (
	defaultFileWalkerWorkerPoolSize = runtime.GOMAXPROCS(0) * 2 // 2x the number of CPUs since the work is not totally CPU bound

	instance *Engine
)

type Engine struct {
	rules              map[string]config.Rule
	rulesBaseRiskScore map[string]float64
	detector           *detect.Detector
	validator          validation.Validator
	semaphore          semaphore.ISemaphore
	chunk              chunk.IChunk
	fileWalkerPool     workerpool.Pool

	ignoredIds    []string
	allowedValues []string
}

type IEngine interface {
	DetectFragment(item plugins.ISourceItem, secretsChannel chan *secrets.Secret, pluginName string) error
	DetectFile(ctx context.Context, item plugins.ISourceItem, secretsChannel chan *secrets.Secret) error
	AddRegexRules(patterns []string) error
	RegisterForValidation(secret *secrets.Secret)
	Score(secret *secrets.Secret, validateFlag bool)
	Validate()
	GetRuleBaseRiskScore(ruleId string) float64
	GetFileWalkerWorkerPool() workerpool.Pool
	Shutdown() error
}

type ctxKey string

const (
	customRegexRuleIdFormat        = "custom-regex-%d"
	CxFileEndMarker                = ";cx-file-end"
	totalLinesKey           ctxKey = "totalLines"
	linesInChunkKey         ctxKey = "linesInChunk"
)

type EngineConfig struct {
	SelectedList []string
	IgnoreList   []string
	SpecialList  []string

	MaxTargetMegabytes int

	IgnoredIds    []string
	AllowedValues []string

	DetectorWorkerPoolSize int
}

func Init(engineConfig *EngineConfig) (IEngine, error) {
	selectedRules := rules.FilterRules(engineConfig.SelectedList, engineConfig.IgnoreList, engineConfig.SpecialList)
	if len(selectedRules) == 0 {
		return nil, fmt.Errorf("no rules were selected")
	}

	rulesToBeApplied := make(map[string]config.Rule)
	rulesBaseRiskScore := make(map[string]float64)
	keywords := make(map[string]struct{})
	for _, rule := range selectedRules { //nolint:gocritic // TODO: refactor to use a pointer
		rulesToBeApplied[rule.Rule.RuleID] = rule.Rule
		rulesBaseRiskScore[rule.Rule.RuleID] = score.GetBaseRiskScore(rule.ScoreParameters.Category, rule.ScoreParameters.RuleType)
		for _, keyword := range rule.Rule.Keywords {
			keywords[strings.ToLower(keyword)] = struct{}{}
		}
	}
	cfg.Rules = rulesToBeApplied
	cfg.Keywords = keywords

	detector := detect.NewDetector(cfg)
	detector.MaxTargetMegaBytes = engineConfig.MaxTargetMegabytes

	fileWalkerWorkerPoolSize := defaultFileWalkerWorkerPoolSize
	if engineConfig.DetectorWorkerPoolSize > 0 {
		fileWalkerWorkerPoolSize = engineConfig.DetectorWorkerPoolSize
	}

	instance = &Engine{
		rules:              rulesToBeApplied,
		rulesBaseRiskScore: rulesBaseRiskScore,
		detector:           detector,
		validator:          *validation.NewValidator(),
		semaphore:          semaphore.NewSemaphore(),
		chunk:              chunk.New(),
		fileWalkerPool:     workerpool.New("file-walker", workerpool.WithWorkers(fileWalkerWorkerPoolSize)),

		ignoredIds:    engineConfig.IgnoredIds,
		allowedValues: engineConfig.AllowedValues,
	}

	return instance, nil
}

func GetEngine() IEngine {
	return instance
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
	fragment.Raw += CxFileEndMarker + "\n"

	values := e.detector.Detect(*fragment)
	for _, value := range values { //nolint:gocritic // rangeValCopy: value is used immediately
		secret, buildErr := buildSecret(ctx, item, value, pluginName)
		if buildErr != nil {
			return fmt.Errorf("failed to build secret: %w", buildErr)
		}
		if !isSecretIgnored(secret, &e.ignoredIds, &e.allowedValues) {
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

func (e *Engine) AddRegexRules(patterns []string) error {
	for idx, pattern := range patterns {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("failed to compile regex rule %s: %w", pattern, err)
		}
		rule := config.Rule{
			Description: "Custom Regex Rule From User",
			RuleID:      fmt.Sprintf(customRegexRuleIdFormat, idx+1),
			Regex:       regex,
			Keywords:    []string{},
		}
		e.rules[rule.RuleID] = rule
	}
	return nil
}

func (e *Engine) RegisterForValidation(secret *secrets.Secret) {
	e.validator.RegisterForValidation(secret)
}

func (e *Engine) Score(secret *secrets.Secret, validateFlag bool) {
	validationStatus := secrets.UnknownResult // default validity
	if validateFlag {
		validationStatus = secret.ValidationStatus
	}
	secret.CvssScore = score.GetCvssScore(e.GetRuleBaseRiskScore(secret.RuleID), validationStatus)
}

func (e *Engine) Validate() {
	e.validator.Validate()
}

func (e *Engine) GetRuleBaseRiskScore(ruleId string) float64 {
	return e.rulesBaseRiskScore[ruleId]
}

func (e *Engine) GetFileWalkerWorkerPool() workerpool.Pool {
	return e.fileWalkerPool
}

func (e *Engine) Shutdown() error {
	if e.fileWalkerPool != nil {
		return e.fileWalkerPool.Stop()
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
			rules := rules.FilterRules(engineConfig.SelectedList, engineConfig.IgnoreList, engineConfig.SpecialList)

			tab := tabwriter.NewWriter(os.Stdout, 1, 2, 2, ' ', 0)

			fmt.Fprintln(tab, "Name\tDescription\tTags\tValidity Check")
			fmt.Fprintln(tab, "----\t----\t----\t----")
			for _, rule := range rules {
				fmt.Fprintf(
					tab,
					"%s\t%s\t%s\t%s\n",
					rule.Rule.RuleID,
					rule.Rule.Description,
					strings.Join(rule.Tags, ","),
					canValidateDisplay[validation.IsCanValidateRule(rule.Rule.RuleID)],
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
	itemId, err := getFindingId(item, &value)
	if err != nil {
		return nil, fmt.Errorf("failed to get finding ID: %w", err)
	}

	startLine, endLine, err := getStartAndEndLines(ctx, pluginName, gitInfo, value)
	if err != nil {
		return nil, fmt.Errorf("failed to get start and end lines for source %s: %w", item.GetSource(), err)
	}

	value.Line = strings.TrimSuffix(value.Line, CxFileEndMarker)
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
		ID:              itemId,
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

func isSecretIgnored(secret *secrets.Secret, ignoredIds, allowedValues *[]string) bool {
	for _, allowedValue := range *allowedValues {
		if secret.Value == allowedValue {
			return true
		}
	}
	for _, ignoredId := range *ignoredIds {
		if secret.ID == ignoredId {
			return true
		}
	}
	return false
}
