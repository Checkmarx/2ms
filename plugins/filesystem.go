package plugins

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const (
	flagFolder      = "path"
	flagProjectName = "project-name"
	flagIgnored     = "ignore-pattern"
)

var ignoredFolders = []string{".git"}

type FileSystemPlugin struct {
	Plugin
	Path        string
	ProjectName string
	Ignored     []string
}

func (p *FileSystemPlugin) GetName() string {
	return "filesystem"
}

func (p *FileSystemPlugin) DefineCommand(items chan ISourceItem, errors chan error) (*cobra.Command, error) {
	var cmd = &cobra.Command{
		Use:   fmt.Sprintf("%s --%s PATH", p.GetName(), flagFolder),
		Short: "Scan local folder",
		Long:  "Scan local folder for sensitive information",
		Run: func(cmd *cobra.Command, args []string) {
			log.Info().Msg("Folder plugin started")

			fileList, err := p.getFiles()
			if err != nil {
				errors <- err
				return
			}
			p.sendItems(items, fileList)

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

	flags.StringSliceVar(&p.Ignored, flagIgnored, []string{}, "Pattern of a folder/file name to ignore")
	flags.StringVar(&p.ProjectName, flagProjectName, "", "Project name to differentiate between filesystem scans")

	return cmd, nil
}

func (p *FileSystemPlugin) getFiles() ([]string, error) {
	fileList := make([]string, 0)
	err := filepath.Walk(p.Path, func(path string, fInfo os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		for _, ignoredFolder := range ignoredFolders {
			if fInfo.Name() == ignoredFolder && fInfo.IsDir() {
				return filepath.SkipDir
			}
		}
		for _, ignoredPattern := range p.Ignored {
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
		return fileList, fmt.Errorf("error while walking through the directory: %w", err)
	}

	return fileList, nil
}

func (p *FileSystemPlugin) sendItems(items chan ISourceItem, fileList []string) {
	defer close(items)
	for _, filePath := range fileList {
		actualFile := p.getItem(filePath)
		items <- *actualFile
	}
}

func (p *FileSystemPlugin) getItem(filePath string) *item {
	log.Debug().Str("file", filePath).Msg("sending file item")

	item := &item{
		ID:     fmt.Sprintf("%s-%s-%s", p.GetName(), p.ProjectName, filePath),
		Source: filePath,
	}
	return item
}
