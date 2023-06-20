package plugins

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const flagFolder = "path"
const flagIgnored = "ignore"

var ignoredFolders = []string{".git"}

type FileSystemPlugin struct {
	Plugin
	Path    string
	Ignored *[]string
}

func (p *FileSystemPlugin) GetName() string {
	return "filesystem"
}

func (p *FileSystemPlugin) DefineCommand(channels Channels) (*cobra.Command, error) {
	var cmd = &cobra.Command{
		Use:   fmt.Sprintf("%s --%s PATH", p.GetName(), flagFolder),
		Short: "Scan local folder",
		Long:  "Scan local folder for sensitive information",
		Run: func(cmd *cobra.Command, args []string) {
			log.Info().Msg("Folder plugin started")
			p.getFiles(channels.Items, channels.Errors, channels.WaitGroup)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&p.Path, flagFolder, "", "Local folder path [required]")
	if err := cmd.MarkFlagDirname(flagFolder); err != nil {
		return nil, fmt.Errorf("error while marking '%s' flag as directory: %w", flagFolder, err)
	}
	if err := cmd.MarkFlagRequired(flagFolder); err != nil {
		return nil, fmt.Errorf("error while marking '%s' flag as required: %w", flagFolder, err)
	}

	p.Ignored = flags.StringArray(flagIgnored, []string{}, "Patterns to ignore")

	return cmd, nil
}

func (p *FileSystemPlugin) getFiles(items chan Item, errs chan error, wg *sync.WaitGroup) {
	fileList := make([]string, 0)
	err := filepath.Walk(p.Path, func(path string, fInfo os.FileInfo, err error) error {
		if err != nil {
			log.Fatal().Err(err).Msg("error while walking through the directory")
		}
		for _, ignoredFolder := range ignoredFolders {
			if fInfo.Name() == ignoredFolder && fInfo.IsDir() {
				return filepath.SkipDir
			}
		}
		for _, ignoredPattern := range *p.Ignored {
			matched, err := filepath.Match(ignoredPattern, filepath.Base(path))
			if err != nil {
				return err
			}
			if matched && fInfo.IsDir() {
				return filepath.SkipDir
			}
			if matched {
				return nil
			}
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

func (p *FileSystemPlugin) getItems(items chan Item, errs chan error, wg *sync.WaitGroup, fileList []string) {
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

func (p *FileSystemPlugin) getItem(wg *sync.WaitGroup, filePath string) (*Item, error) {
	defer wg.Done()
	b, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	content := &Item{
		Content: string(b),
		ID:      filePath,
	}
	return content, nil
}
