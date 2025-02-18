package runner

type FileSystemRunner interface {
	Run(path string, projectName string, ignored []string) (string, error)
}
