package engine

import (
	"crypto/sha1"
	"fmt"
	"github.com/checkmarx/2ms/engine/linecontent"
	"github.com/checkmarx/2ms/engine/score"
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
	"github.com/zricethezav/gitleaks/v8/report"
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
	chunkSize               = 100 * 1_000 // 100kb
	maxPeekSize             = 25 * 1_000  // 10kb
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

func (e *Engine) Detect(item plugins.ISourceItem, secretsChannel chan *secrets.Secret, wg *sync.WaitGroup, errors chan error) {
	defer wg.Done()

	fragment := detect.Fragment{
		Raw:      *item.GetContent(),
		FilePath: item.GetSource(),
	}
	e.detectSecrets(item, fragment, secretsChannel, errors)
}

func (e *Engine) DetectFiles(item plugins.ISourceItem, secretsChannel chan *secrets.Secret, wg *sync.WaitGroup,
	errors chan error /*, sem chan struct{}*/) {
	defer wg.Done()
	//defer func() {
	//	<-sem // Release slot in semaphore
	//}()

	f, err := os.Open(item.GetSource())
	if err != nil {
		errors <- fmt.Errorf("failed to open file %s: %w", item.GetSource(), err)
		return
	}
	defer func() {
		_ = f.Close()
	}()

	fileInfo, err := f.Stat()
	if err != nil {
		errors <- fmt.Errorf("failed to get file info %s: %w", item.GetSource(), err)
		return
	}
	// Check if file size exceeds the limit
	fileSize := fileInfo.Size()
	if e.detector.MaxTargetMegaBytes > 0 {
		rawLength := fileSize / 1000000
		if rawLength > int64(e.detector.MaxTargetMegaBytes) {
			log.Debug().
				Int64("size", rawLength).
				Msg("Skipping file: exceeds --max-target-megabytes")
			return
		}
	}

	var (
		// Buffer to hold file chunks
		reader     = bufio.NewReaderSize(f, chunkSize)
		buf        = make([]byte, chunkSize)
		totalLines = 0
	)
	for {
		n, err := reader.Read(buf)

		// "Callers should always process the n > 0 bytes returned before considering the error err."
		// https://pkg.go.dev/io#Reader
		if n > 0 {
			// Only check the filetype at the start of file
			if totalLines == 0 {
				// TODO: could other optimizations be introduced here?
				if mimetype, err := filetype.Match(buf[:n]); err != nil {
					errors <- fmt.Errorf("failed to detect file type for %s: %w", item.GetSource(), err)
					return
				} else if mimetype.MIME.Type == "application" {
					return // skip binary files
				}
			}

			// Try to split chunks across large areas of whitespace, if possible.
			peekBuf := bytes.NewBuffer(buf[:n])
			if readErr := utils.ReadUntilSafeBoundary(reader, n, maxPeekSize, peekBuf); readErr != nil {
				errors <- fmt.Errorf("failed to read file %s: %w", item.GetSource(), readErr)
				return
			}

			// Count the number of newlines in this chunk
			chunk := peekBuf.String()
			linesInChunk := strings.Count(chunk, "\n")
			totalLines += linesInChunk

			fragment := detect.Fragment{
				Raw:      chunk,
				FilePath: item.GetSource(),
			}
			e.detectSecrets(item, fragment, secretsChannel, errors)
		}

		// Check if we reached the end of the file
		if err != nil {
			if err == io.EOF {
				return
			}
			errors <- fmt.Errorf("failed to read file %s: %w", item.GetSource(), err)
			return
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

func (e *Engine) detectSecrets(item plugins.ISourceItem, fragment detect.Fragment, channel chan *secrets.Secret, errors chan error) {
	for _, value := range e.detector.Detect(fragment) {
		// Build secret
		secret, buildErr := utils.BuildSecret(item, value)
		if buildErr != nil {
			errors <- buildErr
			return
		}
		if !utils.IsSecretIgnored(secret, &e.ignoredIds, &e.allowedValues) {
			channel <- secret
		} else {
			log.Debug().Msgf("Secret %s was ignored", secret.ID)
		}
	}
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
