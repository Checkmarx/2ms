package engine

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/checkmarx/2ms/engine/rules"
	"github.com/checkmarx/2ms/engine/score"
	"github.com/checkmarx/2ms/engine/utils"
	"github.com/checkmarx/2ms/engine/validation"
	"github.com/checkmarx/2ms/lib/secrets"
	"github.com/checkmarx/2ms/plugins"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"golang.org/x/sync/semaphore"
)

type Engine struct {
	rules              map[string]config.Rule
	rulesBaseRiskScore map[string]float64
	detector           detect.Detector
	validator          validation.Validator

	ignoredIds    []string
	allowedValues []string
}

const (
	customRegexRuleIdFormat = "custom-regex-%d"
	ChunkSize               = 100 * 1024      // 100Kib
	MaxPeekSize             = 25 * 1024       // 25Kib
	SmallFileThreshold      = 1 * 1024 * 1024 // 1MiB
)

var (
	// Hols the buffer for reading chunks
	bufPool = sync.Pool{
		New: func() interface{} { return make([]byte, ChunkSize) },
	}
	// Holds the buffer for peeking
	peekBufPool = sync.Pool{
		New: func() interface{} {
			// pre-allocate enough capacity for initial chunk + peek
			return bytes.NewBuffer(make([]byte, 0, ChunkSize+MaxPeekSize))
		},
	}
)

type EngineConfig struct {
	SelectedList []string
	IgnoreList   []string
	SpecialList  []string

	MaxTargetMegabytes int

	IgnoredIds    []string
	AllowedValues []string
}

func Init(engineConfig EngineConfig) (*Engine, error) {
	selectedRules := rules.FilterRules(engineConfig.SelectedList, engineConfig.IgnoreList, engineConfig.SpecialList)
	if len(*selectedRules) == 0 {
		return nil, fmt.Errorf("no rules were selected")
	}

	rulesToBeApplied := make(map[string]config.Rule)
	rulesBaseRiskScore := make(map[string]float64)
	keywords := []string{}
	for _, rule := range *selectedRules {
		rulesToBeApplied[rule.Rule.RuleID] = rule.Rule
		rulesBaseRiskScore[rule.Rule.RuleID] = score.GetBaseRiskScore(rule.ScoreParameters.Category, rule.ScoreParameters.RuleType)
		for _, keyword := range rule.Rule.Keywords {
			keywords = append(keywords, strings.ToLower(keyword))
		}
	}
	cfg.Rules = rulesToBeApplied
	cfg.Keywords = keywords

	detector := detect.NewDetector(cfg)
	detector.MaxTargetMegaBytes = engineConfig.MaxTargetMegabytes

	return &Engine{
		rules:              rulesToBeApplied,
		rulesBaseRiskScore: rulesBaseRiskScore,
		detector:           *detector,
		validator:          *validation.NewValidator(),

		ignoredIds:    engineConfig.IgnoredIds,
		allowedValues: engineConfig.AllowedValues,
	}, nil
}

// DetectFragment detects secrets in the given fragment
func (e *Engine) DetectFragment(item plugins.ISourceItem, secretsChannel chan *secrets.Secret, pluginName string) error {
	fragment := detect.Fragment{
		Raw:      *item.GetContent(),
		FilePath: item.GetSource(),
	}

	return e.DetectSecrets(item, fragment, secretsChannel, pluginName)
}

// DetectFile reads the given file and detects secrets in it
func (e *Engine) DetectFile(ctx context.Context, item plugins.ISourceItem, secretsChannel chan *secrets.Secret,
	memoryBudget int64, sem *semaphore.Weighted) error {
	fi, err := os.Stat(item.GetSource())
	if err != nil {
		return fmt.Errorf("failed to stat %q: %w", item.GetSource(), err)
	}

	fileSize := fi.Size()
	if e.isFileSizeExceedingLimit(fileSize) {
		log.Debug().Int64("size", fileSize/1000000).Msg("Skipping file: exceeds --max-target-megabytes")
		return nil
	}

	// Check if file size exceeds the file threshold, if so, use chunking, if not, read the whole file
	if fileSize > SmallFileThreshold {
		// ChunkSize * 2             ->  raw read buffer + bufio.Reader’s internal slice
		// + (ChunkSize+MaxPeekSize) ->  peekBuf backing slice
		// + (ChunkSize+MaxPeekSize) ->  chunkStr copy
		weight := int64(ChunkSize*4 + MaxPeekSize*2)
		err = utils.AcquireMemoryWeight(ctx, weight, memoryBudget, sem)
		if err != nil {
			return fmt.Errorf("failed to acquire memory: %w", err)
		}
		defer sem.Release(weight)

		return e.DetectChunks(item, secretsChannel)
	} else {
		// fileSize * 2 -> data file bytes and its conversion to string
		weight := fileSize * 2
		err = utils.AcquireMemoryWeight(ctx, weight, memoryBudget, sem)
		if err != nil {
			return fmt.Errorf("failed to acquire memory: %w", err)
		}
		defer sem.Release(weight)

		data, err := os.ReadFile(item.GetSource())
		if err != nil {
			return fmt.Errorf("read small file %q: %w", item.GetSource(), err)
		}
		fragment := detect.Fragment{
			Raw:      string(data),
			FilePath: item.GetSource(),
		}

		return e.DetectSecrets(item, fragment, secretsChannel, "filesystem")
	}
}

// DetectChunks reads the given file in chunks and detects secrets in each chunk
func (e *Engine) DetectChunks(item plugins.ISourceItem, secretsChannel chan *secrets.Secret) error {
	f, err := os.Open(item.GetSource())
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", item.GetSource(), err)
	}
	defer func() {
		_ = f.Close()
	}()

	reader := bufio.NewReaderSize(f, ChunkSize)
	totalLines := 0

	for {
		// Reuse the buffer from the pool
		buf := bufPool.Get().([]byte)
		n, err := reader.Read(buf)

		// "Callers should always process the n > 0 bytes returned before considering the error err."
		// https://pkg.go.dev/io#Reader
		if n > 0 {
			// Only check the filetype at the start of file
			if totalLines == 0 && utils.ShouldSkipFile(buf[:n]) {
				log.Debug().Msgf("Skipping file %s: unsupported file type", item.GetSource())
				return nil
			}

			peekBuf, err := e.processChunk(reader, buf[:n], item, secretsChannel, &totalLines)
			if err != nil {
				// release before early return
				peekBufPool.Put(peekBuf)
				//lint:ignore SA6002 boxing a small slice header is negligible here
				bufPool.Put(buf)
				return err
			}

			// Put the peek buffer back into the pool
			peekBufPool.Put(peekBuf)
		}
		// Put the buffer back into the pool
		//lint:ignore SA6002 boxing a small slice header is negligible here
		bufPool.Put(buf)

		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("failed to read file %s: %w", item.GetSource(), err)
		}
	}
}

// DetectSecrets detects secrets and sends them to the secrets channel
func (e *Engine) DetectSecrets(item plugins.ISourceItem, fragment detect.Fragment, secrets chan *secrets.Secret,
	pluginName string) error {
	for _, value := range e.detector.Detect(fragment) {
		secret, buildErr := utils.BuildSecret(item, value, pluginName)
		if buildErr != nil {
			return fmt.Errorf("failed to build secret: %w", buildErr)
		}
		if !utils.IsSecretIgnored(secret, &e.ignoredIds, &e.allowedValues) {
			secrets <- secret
		} else {
			log.Debug().Msgf("Secret %s was ignored", secret.ID)
		}
	}
	return nil
}

// processChunk reads the next chunk of data from file and detects secrets in it
func (e *Engine) processChunk(reader *bufio.Reader, buf []byte, item plugins.ISourceItem,
	secretsChannel chan *secrets.Secret, totalLines *int) (*bytes.Buffer, error) {
	peekBuf := peekBufPool.Get().(*bytes.Buffer)
	peekBuf.Reset()
	peekBuf.Write(buf) // seed with the current chunk

	// Try to split chunks across large areas of whitespace, if possible
	if readErr := utils.ReadUntilSafeBoundary(reader, len(buf), MaxPeekSize, peekBuf); readErr != nil {
		return peekBuf, fmt.Errorf("failed to read until safe boundary: %w", readErr)
	}

	// Count the number of newlines in this chunk
	chunkStr := peekBuf.String()
	linesInChunk := strings.Count(chunkStr, "\n")
	*totalLines += linesInChunk

	fragment := detect.Fragment{
		Raw:      chunkStr,
		FilePath: item.GetSource(),
	}
	if detectErr := e.DetectSecrets(item, fragment, secretsChannel, "filesystem"); detectErr != nil {
		return peekBuf, fmt.Errorf("failed to detect secrets: %w", detectErr)
	}

	return peekBuf, nil
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

func (e *Engine) RegisterForValidation(secret *secrets.Secret, wg *sync.WaitGroup) {
	defer wg.Done()
	e.validator.RegisterForValidation(secret)
}

func (e *Engine) Score(secret *secrets.Secret, validateFlag bool, wg *sync.WaitGroup) {
	defer wg.Done()
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
			for _, rule := range *rules {
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
