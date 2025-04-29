package engine

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"github.com/checkmarx/2ms/engine/score"
	"github.com/checkmarx/2ms/engine/utils"
	"github.com/h2non/filetype"
	"golang.org/x/sync/semaphore"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/checkmarx/2ms/engine/rules"
	"github.com/checkmarx/2ms/engine/validation"
	"github.com/checkmarx/2ms/lib/secrets"
	"github.com/checkmarx/2ms/plugins"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

type Engine struct {
	rules              map[string]config.Rule
	rulesBaseRiskScore map[string]float64
	detector           detect.Detector
	validator          validation.Validator
	MaxConcurrentFiles int

	ignoredIds    []string
	allowedValues []string
}

const (
	customRegexRuleIdFormat = "custom-regex-%d"
	ChunkSize               = 100 * 1_000     // 100kb
	MaxPeekSize             = 25 * 1_000      // 10kb
	SmallFileThreshold      = 1 * 1024 * 1024 // 1MB
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
	MaxConcurrentFiles int

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
		MaxConcurrentFiles: engineConfig.MaxConcurrentFiles,

		ignoredIds:    engineConfig.IgnoredIds,
		allowedValues: engineConfig.AllowedValues,
	}, nil
}

func (e *Engine) Detect(item plugins.ISourceItem, secretsChannel chan *secrets.Secret) error {
	fragment := detect.Fragment{
		Raw:      *item.GetContent(),
		FilePath: item.GetSource(),
	}

	return e.DetectSecrets(item, fragment, secretsChannel)
}

func (e *Engine) DetectFile(ctx context.Context, item plugins.ISourceItem, secretsChannel chan *secrets.Secret,
	memoryBudget int64, sem *semaphore.Weighted) error {

	fi, err := os.Stat(item.GetSource())
	if err != nil {
		return fmt.Errorf("failed to stat %q: %w", item.GetSource(), err)
	}
	// Check if file size exceeds the limit
	fileSize := fi.Size()
	if e.detector.MaxTargetMegaBytes > 0 {
		rawLength := fileSize / 1000000 // convert to MB
		if rawLength > int64(e.detector.MaxTargetMegaBytes) {
			log.Debug().
				Int64("size", rawLength).
				Msg("Skipping file: exceeds --max-target-megabytes")
			return nil
		}
	}

	// Check if file size exceeds the file threshold, if so, use chunking, if not, read the whole file
	if fileSize > SmallFileThreshold {
		// 2 * ChunkSize    // raw read buffer + bufio.Reader’s internal slice
		// + (ChunkSize+MaxPeekSize)  // peekBuf backing slice
		// + (ChunkSize+MaxPeekSize)  // chunkStr copy
		weight := int64(4*ChunkSize + 2*MaxPeekSize)
		if weight > memoryBudget {
			return fmt.Errorf("buffer size %d exceeds memory budget %d", weight, memoryBudget)
		}

		if err := sem.Acquire(ctx, weight); err != nil {
			return fmt.Errorf("failed to acquire semaphore: %w", err)
		}
		defer sem.Release(weight)

		return e.DetectChunks(item, secretsChannel)
	} else {
		weight := fileSize * 2 // 2x for the data file bytes and its conversion to string
		if weight > memoryBudget {
			return fmt.Errorf("buffer size %d exceeds memory budget %d", weight, memoryBudget)
		}

		if err := sem.Acquire(ctx, weight); err != nil {
			return fmt.Errorf("failed to acquire semaphore: %w", err)
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
		return e.DetectSecrets(item, fragment, secretsChannel)
	}
}

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
			if totalLines == 0 {
				// TODO: could other optimizations be introduced here?
				if mimetype, err := filetype.Match(buf[:n]); err != nil {
					return nil // could not determine file type
				} else if mimetype.MIME.Type == "application" {
					return nil // skip binary files
				}
			}

			// Use a separate buffer for peeking
			peekBuf := peekBufPool.Get().(*bytes.Buffer)
			peekBuf.Reset()
			peekBuf.Write(buf[:n]) // seed with what we've read

			// Try to split chunks across large areas of whitespace, if possible
			if readErr := utils.ReadUntilSafeBoundary(reader, n, MaxPeekSize, peekBuf); readErr != nil {
				// release before early return
				bufPool.Put(buf)
				peekBufPool.Put(peekBuf)
				return fmt.Errorf("failed to read file %s: %w", item.GetSource(), readErr)
			}

			// Count the number of newlines in this chunk
			chunkStr := peekBuf.String()
			linesInChunk := strings.Count(chunkStr, "\n")
			totalLines += linesInChunk

			fragment := detect.Fragment{
				Raw:      chunkStr,
				FilePath: item.GetSource(),
			}
			detectErr := e.DetectSecrets(item, fragment, secretsChannel)
			if detectErr != nil {
				// release before early return
				bufPool.Put(buf)
				peekBufPool.Put(peekBuf)
				return fmt.Errorf("failed to detect secrets in file %s: %w", item.GetSource(), detectErr)
			}

			// Put the peek buffer back into the pool
			peekBufPool.Put(peekBuf)
		}
		// Put the buffer back into the pool
		bufPool.Put(buf)

		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("failed to read file %s: %w", item.GetSource(), err)
		}
	}
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

func (e *Engine) DetectSecrets(item plugins.ISourceItem, fragment detect.Fragment, channel chan *secrets.Secret) error {
	for _, value := range e.detector.Detect(fragment) {
		// Build secret
		secret, buildErr := utils.BuildSecret(item, value)
		if buildErr != nil {
			return fmt.Errorf("failed to build secret: %w", buildErr)
		}
		if !utils.IsSecretIgnored(secret, &e.ignoredIds, &e.allowedValues) {
			channel <- secret
		} else {
			log.Debug().Msgf("Secret %s was ignored", secret.ID)
		}
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
