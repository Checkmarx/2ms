package plugins

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/checkmarx/2ms/lib/utils"
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
)

type GitPlugin struct {
	Plugin
	Channels
	depth           int
	scanAllBranches bool
	projectName     string
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
			p.scanGit(args[0], p.buildScanOptions(), p.Channels.Items, p.Channels.Errors)
			p.WaitGroup.Wait()
			close(items)
		},
	}
	flags := command.Flags()
	flags.BoolVar(&p.scanAllBranches, argScanAllBranches, false, "scan all branches [default: false]")
	flags.IntVar(&p.depth, argDepth, 0, "number of commits to scan from HEAD")
	flags.StringVar(&p.projectName, argProjectName, "", "Project name to differentiate between filesystem scans")
	return command, nil
}

func (p *GitPlugin) buildScanOptions() string {
	options := []string{"--full-history"}
	if p.scanAllBranches {
		options = append(options, "--all")
	}
	if p.depth > 0 {
		options = append(options, fmt.Sprintf("-n %d", p.depth))
	}
	return strings.Join(options, " ")
}

func (p *GitPlugin) scanGit(path string, scanOptions string, itemsChan chan ISourceItem, errChan chan error) {
	diffs, close := p.readGitLog(path, scanOptions, errChan)
	defer close()

	for file := range diffs {
		p.processFileDiff(file, itemsChan)
	}
}

// processFileDiff handles processing a single diff file.
func (p *GitPlugin) processFileDiff(file *gitdiff.File, itemsChan chan ISourceItem) {
	if file.PatchHeader == nil {
		// When parsing the PatchHeader, the token size limit may be exceeded, resulting in a nil value.
		// This scenario is unlikely but may cause the scan to never complete.
		file.PatchHeader = &gitdiff.PatchHeader{}
	}

	log.Debug().Msgf("file: %s; Commit: %s", file.NewName, file.PatchHeader.Title)

	// Skip binary files
	if file.IsBinary {
		return
	}

	// Extract the changes (added and removed) from the text fragments.
	addedChanges, removedChanges := extractChanges(file.TextFragments)

	id := fmt.Sprintf("%s-%s-%s-%s", p.GetName(), p.projectName, file.PatchHeader.SHA, file.NewName)
	source := fmt.Sprintf("git show %s:%s", file.PatchHeader.SHA, file.NewName)

	// If there are added changes, send an item with added content.
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

	// If there are removed changes, send an item with removed content.
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

// extractChanges iterates over the text fragments to compile added and removed changes.
func extractChanges(fragments []*gitdiff.TextFragment) (added string, removed string) {
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
			// Clean up the line content to free memory.
			tf.Lines[i].Line = ""
		}
	}

	return addedBuilder.String(), removedBuilder.String()
}

func (p *GitPlugin) readGitLog(path string, scanOptions string, errChan chan error) (<-chan *gitdiff.File, func()) {
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
		return fmt.Errorf("%s is not a git repository. Please make sure the root path of the provided directory contains a .git subdirectory", args[0])
	}
	if !stat.IsDir() {
		return fmt.Errorf("%s is not a git repository", args[0])
	}
	return nil
}

func GetGitStartAndEndLine(gitInfo *GitInfo, localStartLine, localEndLine int) (int, int) {
	if gitInfo.ContentType == AddedContent {
		return getGitStartAndEndLineAddedContent(gitInfo, localStartLine, localEndLine)
	} else if gitInfo.ContentType == RemovedContent {
		return getGitStartAndEndLineRemovedContent(gitInfo, localStartLine, localEndLine)
	}
	return 0, 0
}

func getGitStartAndEndLineAddedContent(gitInfo *GitInfo, localStartLine, localEndLine int) (int, int) {
	addedIndex := 0
	for _, hunk := range gitInfo.Hunks {
		fileStartLine := int(hunk.NewPosition) - 1
		addedLines := int(hunk.LinesAdded)
		if addedIndex+addedLines <= localStartLine {
			addedIndex += addedLines
			continue
		}
		for _, line := range hunk.Lines {
			if line.Op == gitdiff.OpAdd {
				fileStartLine += 1
				if addedIndex == localStartLine {
					return fileStartLine, (fileStartLine - localStartLine) + localEndLine
				}
				addedIndex += 1
			} else if line.Op == gitdiff.OpContext {
				fileStartLine += 1
			}
		}
	}
	return 0, 0
}

func getGitStartAndEndLineRemovedContent(gitInfo *GitInfo, localStartLine, localEndLine int) (int, int) {
	removedIndex := 0
	for _, hunk := range gitInfo.Hunks {
		fileStartLine := int(hunk.OldPosition) - 1
		deletedLines := int(hunk.LinesDeleted)
		if removedIndex+deletedLines <= localStartLine {
			removedIndex += deletedLines
			continue
		}
		for _, line := range hunk.Lines {
			if line.Op == gitdiff.OpDelete {
				fileStartLine += 1
				if removedIndex == localStartLine {
					return fileStartLine, (fileStartLine - localStartLine) + localEndLine
				}
				removedIndex += 1
			} else if line.Op == gitdiff.OpContext {
				fileStartLine += 1
			}
		}
	}
	return 0, 0
}
