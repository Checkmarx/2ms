package plugins

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const argRepository = "path"

type RepositoryPlugin struct {
	Plugin
	Path string
}

func (p *RepositoryPlugin) DefineSubCommand(cmd *cobra.Command) *cobra.Command {
	var repositoryCmd = &cobra.Command{
		Use:   "repository",
		Short: "Scan repository",
	}

	flags := repositoryCmd.Flags()
	flags.String(argRepository, "", "scan repository folder")
	repositoryCmd.MarkFlagRequired(argRepository)

	return repositoryCmd
}

func (p *RepositoryPlugin) Initialize(cmd *cobra.Command) error {
	flags := cmd.Flags()
	directoryPath, err := flags.GetString(argRepository)
	if err != nil {
		return err
	}

	p.Path = directoryPath
	return nil
}

func (p *RepositoryPlugin) GetItems(items chan Item, errs chan error, wg *sync.WaitGroup) {
	defer wg.Done()

	wg.Add(1)
	go p.getFiles(items, errs, wg)
}

func (p *RepositoryPlugin) getFiles(items chan Item, errs chan error, wg *sync.WaitGroup) {
	defer wg.Done()
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
