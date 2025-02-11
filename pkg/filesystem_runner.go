package runner

import (
	"fmt"
	"sync"

	"github.com/checkmarx/2ms/plugins"
)

type fileSystemRunner struct{}

func NewFileSystemRunner() FileSystemRunner {
	return &fileSystemRunner{}
}

func (r *fileSystemRunner) Run(path string, projectName string, ignored []string) error {
	plugin := &plugins.FileSystemPlugin{
		Path:        path,
		ProjectName: projectName,
		Ignored:     ignored,
	}

	items := make(chan plugins.ISourceItem)
	errors := make(chan error)
	wg := &sync.WaitGroup{}

	go plugin.GetFiles(items, errors, wg)

	for {
		select {
		case item, ok := <-items:
			if !ok {
				items = nil
			} else {
				fmt.Println("Item:", item)
			}
		case err, ok := <-errors:
			if !ok {
				errors = nil
			} else {
				fmt.Println("Error:", err)
			}
		}

		if items == nil && errors == nil {
			break
		}
	}

	wg.Wait()
	return nil
}
