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
	IsAddedContent   bool
	IsDeletedContent bool
	Hunks            []*gitdiff.TextFragment
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
		if file.PatchHeader == nil {
			// While parsing the PatchHeader, the token size limit may be exceeded, resulting in a nil value.
			// This scenario is unlikely, but it causes the scan to never complete.
			file.PatchHeader = &gitdiff.PatchHeader{}
		}

		log.Debug().Msgf("file: %s; Commit: %s", file.NewName, file.PatchHeader.Title)
		if file.IsBinary || file.IsDelete {
			continue
		}

		var addedBuilder, deletedBuilder strings.Builder
		for _, tf := range file.TextFragments {
			if tf == nil {
				continue
			}
			addedBuilder.WriteString(tf.Raw(gitdiff.OpAdd))
			deletedBuilder.WriteString(tf.Raw(gitdiff.OpDelete))
		}

		fileAddedChanges := addedBuilder.String()
		fileDeletedChanges := deletedBuilder.String()
		id := fmt.Sprintf("%s-%s-%s-%s", p.GetName(), p.projectName, file.PatchHeader.SHA, file.NewName)
		source := fmt.Sprintf("git show %s:%s", file.PatchHeader.SHA, file.NewName)

		if fileAddedChanges != "" {
			itemsChan <- item{
				Content: &fileAddedChanges,
				ID:      id,
				Source:  source,
				GitInfo: &GitInfo{
					Hunks:          file.TextFragments,
					IsAddedContent: true,
				},
			}
		}

		if fileDeletedChanges != "" {
			itemsChan <- item{
				Content: &fileDeletedChanges,
				ID:      id,
				Source:  source,
				GitInfo: &GitInfo{
					Hunks:            file.TextFragments,
					IsDeletedContent: true,
				},
			}
		}
	}
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
	if gitInfo.IsAddedContent {
		return getGitStartAndEndLineAddedContent(gitInfo, localStartLine, localEndLine)
	}
	if gitInfo.IsDeletedContent {
		return getGitStartAndEndLineDeletedContent(gitInfo, localStartLine, localEndLine)
	}
	return 0, 0
}

func getGitStartAndEndLineAddedContent(gitInfo *GitInfo, localStartLine, localEndLine int) (int, int) {
	addedIndex := 0
	for _, hunk := range gitInfo.Hunks {
		globalStartLine := int(hunk.NewPosition) - 1
		for _, line := range hunk.Lines {
			if line.Op == gitdiff.OpAdd {
				globalStartLine += 1
				if addedIndex == localStartLine {
					return globalStartLine, (globalStartLine - localStartLine) + localEndLine
				}
				addedIndex += 1
			} else if line.Op == gitdiff.OpContext {
				globalStartLine += 1
			}
		}
	}
	return 0, 0
}

func getGitStartAndEndLineDeletedContent(gitInfo *GitInfo, localStartLine, localEndLine int) (int, int) {
	deletedIndex := 0
	for _, hunk := range gitInfo.Hunks {
		globalStartLine := int(hunk.OldPosition) - 1
		for _, line := range hunk.Lines {
			if line.Op == gitdiff.OpDelete {
				globalStartLine += 1
				if deletedIndex == localStartLine {
					return globalStartLine, (globalStartLine - localStartLine) + localEndLine
				}
				deletedIndex += 1
			} else if line.Op == gitdiff.OpContext {
				globalStartLine += 1
			}
		}
	}
	return 0, 0
}
