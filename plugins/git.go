package plugins

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/checkmarx/2ms/v4/lib/utils"
	"github.com/gitleaks/go-gitdiff/gitdiff"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	git "github.com/zricethezav/gitleaks/v8/sources"
)

type DiffType int

const (
	AddedContent DiffType = iota
	RemovedContent

	maxChunkSize = 256 * 1024 // 256KB max chunk size for git diff content (optimized for regexp)
)

const (
	argDepth           = "depth"
	argScanAllBranches = "all-branches"
	argProjectName     = "project-name"
	argBaseCommit      = "base-commit"
	unknownCommit      = "unknown"

	added   stringBuilderType = "added"
	removed stringBuilderType = "removed"

	defaultPreAllocCount = 900
)

type stringBuilderType string

type GitPlugin struct {
	Plugin
	Channels
	depth           int
	scanAllBranches bool
	projectName     string
	baseCommit      string
	gitChangesPool  *gitChangesPool
}

func NewGitPlugin() IPlugin {
	return &GitPlugin{
		gitChangesPool: newGitChangesPool(defaultPreAllocCount),
	}
}

type GitInfo struct {
	Hunks       []*gitdiff.TextFragment
	ContentType DiffType
}

// gitdiffChunk represents a chunk of git diff content
type gitdiffChunk struct {
	Added   string
	Removed string
}

// StringBuilderPool provides thread-safe object pooling for string builders
type StringBuilderPool struct {
	pool        sync.Pool
	gets        atomic.Int64
	puts        atomic.Int64
	discards    atomic.Int64
	news        atomic.Int64
	maxSize     int
	builderType stringBuilderType
}

type gitChangesPool struct {
	sync.Pool

	slicePoolGets     atomic.Int64
	slicePoolPuts     atomic.Int64
	slicePoolDiscards atomic.Int64
	slicePoolNews     atomic.Int64
}

func newGitChangesPool(preAllocCount int) *gitChangesPool {
	pool := &gitChangesPool{}
	pool.Pool = sync.Pool{
		New: func() interface{} {
			pool.slicePoolNews.Add(1)
			slice := make([]gitdiffChunk, 0, 16) // Initial capacity for 16 chunks
			return &slice
		},
	}

	for i := 0; i < preAllocCount; i++ {
		pool.getSlice()
	}

	return pool
}

var (
	addedPool   = newStringBuilderPool(added, 4096, 512*1024, defaultPreAllocCount)   // 4KB initial, 512KB max, 900 pre-allocated
	removedPool = newStringBuilderPool(removed, 4096, 512*1024, defaultPreAllocCount) // 4KB initial, 512KB max, 900 pre-allocated
)

func (p *GitPlugin) GetName() string {
	return "git"
}

func newStringBuilderPool(builderType stringBuilderType, initialCap, maxSize, preAllocCount int) *StringBuilderPool {
	sbPool := &StringBuilderPool{
		builderType: builderType,
		maxSize:     maxSize,
	}
	sbPool.pool = sync.Pool{
		New: func() interface{} {
			sbPool.news.Add(1)
			sb := &strings.Builder{}
			sb.Grow(initialCap) // Pre-allocate to reduce early growth
			return sb
		},
	}

	// Pre-populate the pool with builders to avoid initial allocation pressure
	if preAllocCount > 0 {
		for i := 0; i < preAllocCount; i++ {
			sb := &strings.Builder{}
			sb.Grow(initialCap)
			sbPool.pool.Put(sb)
		}
	}

	return sbPool
}

// Get retrieves a string builder from the pool
func (p *StringBuilderPool) Get() *strings.Builder {
	p.gets.Add(1)
	sb := p.pool.Get().(*strings.Builder)
	return sb
}

// Put returns a string builder to the pool with size limits
func (p *StringBuilderPool) Put(sb *strings.Builder) {
	if sb == nil {
		return
	}

	// Don't pool builders that grew too large (prevents memory bloat)
	if sb.Cap() > p.maxSize {
		p.discards.Add(1)
		return
	}

	// Reset content but keep capacity
	sb.Reset()
	p.puts.Add(1)
	p.pool.Put(sb)
}

// Stats returns pool efficiency statistics
func (p *StringBuilderPool) Stats() (gets, puts, discards, news int64, efficiency float64) {
	g := p.gets.Load()
	pt := p.puts.Load()
	d := p.discards.Load()
	n := p.news.Load()

	if g > 0 {
		eff := float64(pt) / float64(g) * 100
		return g, pt, d, n, eff
	}
	return g, pt, d, n, 0.0
}

func (p *gitChangesPool) getSlice() []gitdiffChunk {
	p.slicePoolGets.Add(1)
	return *p.Get().(*[]gitdiffChunk)
}

func (p *gitChangesPool) putSlice(chunks []gitdiffChunk) {
	if cap(chunks) > 32 { // Don't pool slices larger than 64 elements
		p.slicePoolDiscards.Add(1)
		return
	}
	chunks = chunks[:0] // Reset length but keep capacity
	p.slicePoolPuts.Add(1)
	p.Put(&chunks)
}

func (p *gitChangesPool) Stats() (gets, puts, discards, news int64, efficiency float64) {
	g := p.slicePoolGets.Load()
	pt := p.slicePoolPuts.Load()
	d := p.slicePoolDiscards.Load()
	n := p.slicePoolNews.Load()

	if g > 0 {
		eff := float64(pt) / float64(g) * 100
		return g, pt, d, n, eff
	}
	return g, pt, d, n, 0.0
}

// PrintPoolStats logs the current efficiency statistics for all pools
func (p *gitChangesPool) Print() {
	getsA, putsA, discardsA, newsA, effA := addedPool.Stats()
	log.Trace().
		Str("pool_type", "string_builder").
		Str("content_type", string(added)).
		Int64("news", newsA).
		Int64("gets", getsA).
		Int64("puts", putsA).
		Int64("discards", discardsA).
		Float64("efficiency_percent", effA).
		Msg("Added content string builders")

	getsR, putsR, discardsR, newsR, effR := removedPool.Stats()
	log.Trace().
		Str("pool_type", "string_builder").
		Str("content_type", string(removed)).
		Int64("news", newsR).
		Int64("gets", getsR).
		Int64("puts", putsR).
		Int64("discards", discardsR).
		Float64("efficiency_percent", effR).
		Msg("Removed content string builders")

	sliceGets, slicePuts, sliceDiscards, sliceNews, sliceEff := p.Stats()

	log.Trace().
		Str("pool_type", "gitdiffChunk").
		Int64("gets", sliceGets).
		Int64("puts", slicePuts).
		Int64("discards", sliceDiscards).
		Int64("new_allocations", sliceNews).
		Float64("efficiency_percent", sliceEff).
		Msg("gitdiffChunk slice arrays")

	stringBuilderGets := getsA + getsR
	stringBuilderPuts := putsA + putsR
	stringBuilderDiscards := discardsA + discardsR
	var stringBuilderEff float64
	if stringBuilderGets > 0 {
		stringBuilderEff = float64(stringBuilderPuts) / float64(stringBuilderGets) * 100
	}

	log.Trace().
		Str("summary_type", "string_builders").
		Int64("total_gets", stringBuilderGets).
		Int64("total_puts", stringBuilderPuts).
		Int64("total_discards", stringBuilderDiscards).
		Float64("combined_efficiency_percent", stringBuilderEff).
		Msg("All string builder pools combined")

	log.Trace().
		Str("summary_type", "slices").
		Int64("total_gets", sliceGets).
		Int64("total_puts", slicePuts).
		Int64("total_discards", sliceDiscards).
		Int64("total_new_allocations", sliceNews).
		Float64("efficiency_percent", sliceEff).
		Msg("Slice pool summary")
}

func (p *GitPlugin) DefineCommand(items chan ISourceItem, errors chan error) (*cobra.Command, error) {
	p.Channels = Channels{
		Items:     items,
		Errors:    errors,
		WaitGroup: &sync.WaitGroup{},
	}

	command := &cobra.Command{
		Use:   fmt.Sprintf("%s <CLONED_REPO>", p.GetName()),
		Short: "Scan local Git repository",
		Long:  "Scan local Git repository for sensitive information.",
		Args:  cobra.MatchAll(cobra.ExactArgs(1), validGitRepoArgs),
		Run: func(cmd *cobra.Command, args []string) {
			log.Info().Msg("Git plugin started")
			p.scanGit(args[0], p.buildScanOptions(), p.Items, p.Errors)
			p.WaitGroup.Wait()
			close(items)
		},
	}
	flags := command.Flags()
	flags.BoolVar(&p.scanAllBranches, argScanAllBranches, false, "scan all branches [default: false]")
	flags.IntVar(&p.depth, argDepth, 0, "number of commits to scan from HEAD")
	flags.StringVar(&p.projectName, argProjectName, "", "Project name to differentiate between filesystem scans")
	flags.StringVar(&p.baseCommit, argBaseCommit, "", "Base commit to scan commits between base and HEAD")
	return command, nil
}

func (p *GitPlugin) buildScanOptions() string {
	options := []string{"--full-history"}
	if p.scanAllBranches {
		options = append(options, "--all")
	}

	// If base commit is specified, use commit range instead of depth
	if p.baseCommit != "" {
		options = append(options, fmt.Sprintf("%s..HEAD", p.baseCommit))
	} else if p.depth > 0 {
		options = append(options, fmt.Sprintf("-n %d", p.depth))
	}

	return strings.Join(options, " ")
}

func (p *GitPlugin) scanGit(path, scanOptions string, itemsChan chan ISourceItem, errChan chan error) {
	diffs, wait := p.readGitLog(path, scanOptions, errChan)
	defer wait()

	for file := range diffs {
		p.processFileDiff(file, itemsChan)
	}

	// Print pool statistics after scan completes
	if log.Trace().Enabled() {
		p.gitChangesPool.Print()
	}
}

// processFileDiff handles processing a single diff file with chunked processing.
func (p *GitPlugin) processFileDiff(file *gitdiff.File, itemsChan chan ISourceItem) {
	if file == nil {
		return
	}

	if file.PatchHeader == nil {
		// When parsing the PatchHeader, the token size limit may be exceeded, resulting in a nil value
		// This scenario is unlikely but may cause the scan to never complete
		file.PatchHeader = &gitdiff.PatchHeader{}
		file.PatchHeader.SHA = unknownCommit
	}

	fileName := file.NewName
	if file.IsDelete {
		fileName = file.OldName
	}

	log.Debug().Msgf("file: %s; Commit: %s", fileName, file.PatchHeader.Title)

	// Skip binary files
	if file.IsBinary {
		return
	}

	chunks := extractChanges(p.gitChangesPool, file.TextFragments)

	for _, chunk := range chunks {
		id := fmt.Sprintf("%s-%s-%s-%s", p.GetName(), p.projectName, file.PatchHeader.SHA, fileName)
		source := fmt.Sprintf("git show %s:%s", file.PatchHeader.SHA, fileName)

		if chunk.Added != "" {
			itemsChan <- item{
				Content: &chunk.Added,
				ID:      id,
				Source:  source,
				GitInfo: &GitInfo{
					Hunks:       file.TextFragments,
					ContentType: AddedContent,
				},
			}
		}

		if chunk.Removed != "" {
			itemsChan <- item{
				Content: &chunk.Removed,
				ID:      id,
				Source:  source,
				GitInfo: &GitInfo{
					Hunks:       file.TextFragments,
					ContentType: RemovedContent,
				},
			}
		}
	}

	p.gitChangesPool.putSlice(chunks)
}

// extractChanges performs memory-bounded chunked processing of git diff fragments
func extractChanges(changesPool *gitChangesPool, fragments []*gitdiff.TextFragment) []gitdiffChunk {
	chunks := changesPool.getSlice()
	currentAdded := addedPool.Get()
	defer addedPool.Put(currentAdded)
	currentRemoved := removedPool.Get()
	defer removedPool.Put(currentRemoved)

	currentSize := 0

	for _, tf := range fragments {
		if tf == nil {
			continue
		}

		for i := range tf.Lines {
			line := tf.Lines[i].Line
			lineSize := len(line)

			// Skip excessively large lines (potential issue)
			if lineSize > 1024*1024 { // 1MB line limit
				tf.Lines[i].Line = "" // Clear line to free memory
				continue
			}

			// Check if adding this line would exceed chunk size
			if currentSize > 0 && currentSize+lineSize > maxChunkSize {
				// Create chunk with current content before adding this line
				chunks = append(chunks, gitdiffChunk{
					Added:   currentAdded.String(),
					Removed: currentRemoved.String(),
				})

				// Reset builders for next chunk
				currentAdded.Reset()
				currentRemoved.Reset()
				currentSize = 0
			}

			switch tf.Lines[i].Op {
			case gitdiff.OpAdd:
				currentAdded.WriteString(line)
				currentSize += lineSize
			case gitdiff.OpDelete:
				currentRemoved.WriteString(line)
				currentSize += lineSize
			}

			// Clear line immediately to free memory
			tf.Lines[i].Line = ""
		}
	}

	// Final chunk
	if currentSize > 0 {
		chunks = append(chunks, gitdiffChunk{
			Added:   currentAdded.String(),
			Removed: currentRemoved.String(),
		})
	}

	return chunks
}

func (p *GitPlugin) readGitLog(path, scanOptions string, errChan chan error) (<-chan *gitdiff.File, func()) {
	gitLog, err := git.NewGitLogCmd(path, scanOptions)
	if err != nil {
		errChan <- fmt.Errorf("error while scanning git repository: %w", err)
	}
	wait := func() {
		err := gitLog.Wait()
		if err != nil {
			errChan <- fmt.Errorf("error while waiting for git log to finish: %w", err)
		}
	}
	log.Debug().Msgf("scanning git repository: %s", path)

	p.WaitGroup.Add(1)
	go utils.BindChannels[error](gitLog.ErrCh(), errChan, p.WaitGroup)

	return gitLog.DiffFilesCh(), wait
}

func validGitRepoArgs(cmd *cobra.Command, args []string) error {
	stat, err := os.Stat(args[0])
	if err != nil {
		return err
	}
	if !stat.IsDir() {
		return fmt.Errorf("%s is not a directory", args[0])
	}
	gitFolder := fmt.Sprintf("%s/.git", args[0])
	stat, err = os.Stat(gitFolder)
	if err != nil {
		return fmt.Errorf(
			"%s is not a git repository. Please make sure the root path of the provided directory contains a .git subdirectory",
			args[0],
		)
	}
	if !stat.IsDir() {
		return fmt.Errorf("%s is not a git repository", args[0])
	}
	return nil
}

// GetGitStartAndEndLine walks the diff hunks and discover the actual start and end lines of the file
func GetGitStartAndEndLine(gitInfo *GitInfo, localStartLine, localEndLine int) (int, int, error) {
	hunkPosition, hunkCount, relevantOp, err := getHunkPosAndCount(gitInfo)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get hunk position and count: %w", err)
	}

	diffLines := 0 // Tracks how many lines have been processed in the diff
	for _, hunk := range gitInfo.Hunks {
		// If the hunk ends before the start line in the file diff, skip it
		totalLines := hunkCount(hunk)
		if diffLines+totalLines <= localStartLine {
			diffLines += totalLines
			continue
		}

		// Get the start line of the hunk in the file diff and walk through its lines to find the actual start line
		fileStartLine := hunkPosition(hunk) - 1
		for _, line := range hunk.Lines {
			switch line.Op {
			case relevantOp:
				fileStartLine += 1
				if diffLines == localStartLine {
					fileEndLine := fileStartLine + (localEndLine - localStartLine)
					return fileStartLine, fileEndLine, nil
				}
				diffLines += 1
			case gitdiff.OpContext: // Context lines are not counted in the diff
				fileStartLine += 1
			default:
			}
		}
	}
	// Did not find the start line in any hunk
	return 0, 0, fmt.Errorf("failed to find start line %d in hunks", localStartLine)
}

// getHunkPosAndCount returns the functions to get the position and count of hunks based on the content type
func getHunkPosAndCount( //nolint:gocritic // paramTypeCombine: complex return types make this necessary
	gitInfo *GitInfo,
) (hunkPos func(h *gitdiff.TextFragment) int, hunkCount func(h *gitdiff.TextFragment) int, matchOp gitdiff.LineOp, err error) {
	switch gitInfo.ContentType {
	case AddedContent:
		hunkPos = func(h *gitdiff.TextFragment) int { return int(h.NewPosition) }
		hunkCount = func(h *gitdiff.TextFragment) int { return int(h.LinesAdded) }
		matchOp = gitdiff.OpAdd
	case RemovedContent:
		hunkPos = func(h *gitdiff.TextFragment) int { return int(h.OldPosition) }
		hunkCount = func(h *gitdiff.TextFragment) int { return int(h.LinesDeleted) }
		matchOp = gitdiff.OpDelete
	default:
		err = fmt.Errorf("unknown content type: %d", gitInfo.ContentType)
	}
	return
}
