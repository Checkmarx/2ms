package reporting

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/checkmarx/2ms/v3/lib/config"
	"github.com/checkmarx/2ms/v3/lib/secrets"
	"github.com/rs/zerolog/log"
)

const (
	jsonFormat      = "json"
	longYamlFormat  = "yaml"
	shortYamlFormat = "yml"
	sarifFormat     = "sarif"
)

type Report struct {
	TotalItemsScanned int                          `json:"totalItemsScanned"`
	TotalSecretsFound int                          `json:"totalSecretsFound"`
	Results           map[string][]*secrets.Secret `json:"results"`
}

func Init() *Report {
	return &Report{
		Results: make(map[string][]*secrets.Secret),
	}
}
func (r *Report) ShowReport(format string, cfg *config.Config) error {
	output, err := r.GetOutput(format, cfg)
	if err != nil {
		return err
	}

	log.Info().Msg("\n" + output)
	return nil
}

func (r *Report) WriteFile(reportPath []string, cfg *config.Config) error {
	for _, path := range reportPath {
		err := os.MkdirAll(filepath.Dir(path), 0750)
		if err != nil {
			return err
		}

		file, err := os.Create(path)
		if err != nil {
			return err
		}

		fileExtension := filepath.Ext(path)
		format := strings.TrimPrefix(fileExtension, ".")
		output, err := r.GetOutput(format, cfg)
		if err != nil {
			return err
		}

		_, err = file.WriteString(output)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *Report) GetOutput(format string, cfg *config.Config) (string, error) {
	var output string
	var err error
	switch format {
	case jsonFormat:
		output, err = writeJson(r)
	case longYamlFormat, shortYamlFormat:
		output, err = writeYaml(r)
	case sarifFormat:
		output, err = writeSarif(r, cfg)
	}
	return output, err
}
