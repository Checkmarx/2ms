package plugins

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const flagRepository = "path"

type RepositoryPlugin struct {
	Plugin
	Path string
}

func (p *RepositoryPlugin) GetName() string {
	return "repository"
}

func (p *RepositoryPlugin) DefineCommand(channels Channels) (*cobra.Command, error) {
	var cmd = &cobra.Command{
		Use:   fmt.Sprintf("%s --%s PATH", p.GetName(), flagRepository),
		Short: "Scan local repository",
		Long:  "Scan local repository for sensitive information",
		Run: func(cmd *cobra.Command, args []string) {
			log.Info().Msg("Repository plugin started")
			p.getFiles(channels.Items, channels.Errors, channels.WaitGroup)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&p.Path, flagRepository, "", "Local repository path [required]")
	if err := cmd.MarkFlagDirname(flagRepository); err != nil {
		return nil, fmt.Errorf("error while marking '%s' flag as directory: %w", flagRepository, err)
	}
	if err := cmd.MarkFlagRequired(flagRepository); err != nil {
		return nil, fmt.Errorf("error while marking '%s' flag as required: %w", flagRepository, err)
	}

	return cmd, nil
}

func (p *RepositoryPlugin) getFiles(items chan Item, errs chan error, wg *sync.WaitGroup) {
	fileList := make([]string, 0)
	err := filepath.Walk(p.Path, func(path string, fInfo os.FileInfo, err error) error {
		if err != nil {
			log.Fatal().Err(err).Msg("error while walking through the directory")
		}
		if fInfo.Name() == ".git" && fInfo.IsDir() {
			return filepath.SkipDir
		}
		if fInfo.Size() == 0 {
			return nil
		}
		if !fInfo.IsDir() {
			fileList = append(fileList, path)
		}
		return err
	})

	if err != nil {
		log.Fatal().Err(err).Msg("error while walking through the directory")
	}

	p.getItems(items, errs, wg, fileList)
}

func (p *RepositoryPlugin) getItems(items chan Item, errs chan error, wg *sync.WaitGroup, fileList []string) {
	for _, filePath := range fileList {
		wg.Add(1)
		go func(filePath string) {
			actualFile, err := p.getItem(wg, filePath)
			if err != nil {
				errs <- err
				return
			}
			items <- *actualFile
		}(filePath)
	}
}

func (p *RepositoryPlugin) getItem(wg *sync.WaitGroup, filePath string) (*Item, error) {
	defer wg.Done()
	b, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	content := &Item{
		Content: string(b),
		Source:  filePath,
		ID:      filePath,
	}
	return content, nil
}
