package plugins

import (
	"errors"
	"github.com/spf13/cobra"
	"log"
	"os"
	"path/filepath"
	"sync"
)

const argRepository = "path"

type RepositoryPlugin struct {
	Plugin
	Path string
}

func (p *RepositoryPlugin) IsEnabled() bool {
	return p.Enabled
}

func (p *RepositoryPlugin) DefineCommandLineArgs(cmd *cobra.Command) error {
	flags := cmd.Flags()
	flags.String(argRepository, "", "scan repository folder")
	return nil
}

func (p *RepositoryPlugin) Initialize(cmd *cobra.Command) error {
	flags := cmd.Flags()
	directoryPath, _ := flags.GetString(argRepository)
	if directoryPath == "" {
		return errors.New("path to repository missing. Plugin initialization failed")
	}

	p.Path = directoryPath
	p.Enabled = true
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
			log.Fatalf(err.Error())
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
		log.Fatalf(err.Error())
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
