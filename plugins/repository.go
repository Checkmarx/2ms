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
	flags.StringP(argRepository, "", "", "scan repository folder")
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

	go p.getFiles(items, errs, wg)
	wg.Add(1)
}

func (p *RepositoryPlugin) getFiles(items chan Item, errs chan error, wg *sync.WaitGroup) {
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
		panic(err)
	}

	go p.getItems(items, errs, wg, fileList)
}

func (p *RepositoryPlugin) getItems(items chan Item, errs chan error, wg *sync.WaitGroup, fileList []string) {
	defer wg.Done()

	for _, filePath := range fileList {
		actualFile, err := p.getItem(filePath)
		if err != nil {
			errs <- err
			return
		}
		items <- *actualFile
	}
}

func (p *RepositoryPlugin) getItem(filePath string) (*Item, error) {
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
