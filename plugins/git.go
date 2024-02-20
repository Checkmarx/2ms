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
	"github.com/zricethezav/gitleaks/v8/detect/git"
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

func (p *GitPlugin) GetName() string {
	return "git"
}

func (p *GitPlugin) DefineCommand(items chan Item, errors chan error) (*cobra.Command, error) {
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

func (p *GitPlugin) scanGit(path string, scanOptions string, itemsChan chan Item, errChan chan error) {
	diffs, close := p.readGitLog(path, scanOptions, errChan)
	defer close()

	for file := range diffs {
		log.Debug().Msgf("file: %s; Commit: %s", file.NewName, file.PatchHeader.Title)
		if file.IsBinary || file.IsDelete {
			continue
		}

		fileChanges := ""
		for _, textFragment := range file.TextFragments {
			if textFragment != nil {
				raw := textFragment.Raw(gitdiff.OpAdd)
				fileChanges += raw
			}
		}
		if fileChanges != "" {
			itemsChan <- Item{
				Content: fileChanges,
				ID:      fmt.Sprintf("%s-%s-%s-%s", p.GetName(), p.projectName, file.PatchHeader.SHA, file.NewName),
				Source:  fmt.Sprintf("git show %s:%s", file.PatchHeader.SHA, file.NewName),
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
