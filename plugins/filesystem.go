package plugins

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
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

			p.getFiles(items, errors)
			close(items)
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

func (p *FileSystemPlugin) getFiles(items chan ISourceItem, errs chan error) {
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
		errs <- fmt.Errorf("error while walking through the directory: %w", err)
		time.Sleep(time.Second) // Temporary fix for incorrect non-error exits; needs a better solution.
		return
	}

	p.getItems(items, errs, fileList)
}

func (p *FileSystemPlugin) getItems(items chan ISourceItem, errs chan error, fileList []string) {
	g := errgroup.Group{}
	g.SetLimit(1000)
	for _, filePath := range fileList {
		g.Go(func() error {
			actualFile, err := p.getItem(filePath)
			if err != nil {
				errs <- err
				time.Sleep(time.Second) // Temporary fix for incorrect non-error exits; needs a better solution.
				return nil
			}
			items <- *actualFile
			return nil
		})
	}
	g.Wait()
}

func (p *FileSystemPlugin) getItem(filePath string) (*item, error) {
	log.Debug().Str("file", filePath).Msg("reading file")
	b, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	content := string(b)
	item := &item{
		Content: &content,
		ID:      fmt.Sprintf("%s-%s-%s", p.GetName(), p.ProjectName, filePath),
		Source:  filePath,
	}
	return item, nil
}
