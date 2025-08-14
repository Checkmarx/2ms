package plugins

import (
	"fmt"
	"os"
	"strings"
	"sync"

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
)

const (
	argDepth           = "depth"
	argScanAllBranches = "all-branches"
	argProjectName     = "project-name"
	argBaseCommit      = "base-commit"
	unknownCommit      = "unknown"
)

type GitPlugin struct {
	Plugin
	Channels
	depth           int
	scanAllBranches bool
	projectName     string
	baseCommit      string
}

type GitInfo struct {
	Hunks       []*gitdiff.TextFragment
	ContentType DiffType
}

func (p *GitPlugin) GetName() string {
	return "git"
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
}

// processFileDiff handles processing a single diff file.
func (p *GitPlugin) processFileDiff(file *gitdiff.File, itemsChan chan ISourceItem) {
	if file.PatchHeader == nil {
		// When parsing the PatchHeader, the token size limit may be exceeded, resulting in a nil value
		// This scenario is unlikely but may cause the scan to never complete
		file.PatchHeader = &gitdiff.PatchHeader{}
		file.PatchHeader.SHA = unknownCommit
	}

	log.Debug().Msgf("file: %s; Commit: %s", file.NewName, file.PatchHeader.Title)

	// Skip binary files
	if file.IsBinary {
		return
	}

	// Extract the changes (added and removed) from the text fragments
	addedChanges, removedChanges := extractChanges(file.TextFragments)

	var fileName string
	if file.IsDelete {
		fileName = file.OldName
	} else {
		fileName = file.NewName
	}
	id := fmt.Sprintf("%s-%s-%s-%s", p.GetName(), p.projectName, file.PatchHeader.SHA, fileName)
	source := fmt.Sprintf("git show %s:%s", file.PatchHeader.SHA, fileName)

	// If there are added changes, send an item with added content
	if addedChanges != "" {
		itemsChan <- item{
			Content: &addedChanges,
			ID:      id,
			Source:  source,
			GitInfo: &GitInfo{
				Hunks:       file.TextFragments,
				ContentType: AddedContent,
			},
		}
	}

	// If there are removed changes, send an item with removed content
	if removedChanges != "" {
		itemsChan <- item{
			Content: &removedChanges,
			ID:      id,
			Source:  source,
			GitInfo: &GitInfo{
				Hunks:       file.TextFragments,
				ContentType: RemovedContent,
			},
		}
	}
}

// extractChanges iterates over the text fragments to compile added and removed changes
func extractChanges(fragments []*gitdiff.TextFragment) (added, removed string) {
	var addedBuilder, removedBuilder strings.Builder

	for _, tf := range fragments {
		if tf == nil {
			continue
		}
		for i := range tf.Lines {
			switch tf.Lines[i].Op {
			case gitdiff.OpAdd:
				addedBuilder.WriteString(tf.Lines[i].Line)
			case gitdiff.OpDelete:
				removedBuilder.WriteString(tf.Lines[i].Line)
			default:
			}
			// Clean up the line content to free memory
			tf.Lines[i].Line = ""
		}
	}

	return addedBuilder.String(), removedBuilder.String()
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
