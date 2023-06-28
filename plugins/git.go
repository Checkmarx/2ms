package plugins

import (
	"fmt"
	"os"

	"github.com/gitleaks/go-gitdiff/gitdiff"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/zricethezav/gitleaks/v8/detect/git"
)

type GitPlugin struct {
	Plugin
	Channels
}

func (p *GitPlugin) GetName() string {
	return "git"
}

func (p *GitPlugin) DefineCommand(channels Channels) (*cobra.Command, error) {
	p.Channels = channels

	command := &cobra.Command{
		Use:   fmt.Sprintf("%s <CLONED_REPO>", p.GetName()),
		Short: "Scan local Git repository",
		Long:  "Scan local Git repository for sensitive information.",
		Args:  cobra.MatchAll(cobra.ExactArgs(1), validGitRepoArgs),
		Run: func(cmd *cobra.Command, args []string) {
			log.Info().Msg("Git plugin started")
			scanGit(args[0], channels.Items, channels.Errors)
		},
	}

	return command, nil
}

func scanGit(path string, itemsChan chan Item, errChan chan error) {
	fileChan, err := git.GitLog(path, "")
	if err != nil {
		errChan <- fmt.Errorf("error while scanning git repository: %w", err)
	}
	log.Debug().Msgf("scanned git repository: %s", path)

	for file := range fileChan {
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
				ID:      fmt.Sprintf("git show %s:%s", file.PatchHeader.SHA, file.NewName),
			}
		}
	}
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
		return err
	}
	if !stat.IsDir() {
		return fmt.Errorf("%s is not a git repository", args[0])
	}
	return nil
}
