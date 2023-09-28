package tests

import (
	"encoding/json"
	"fmt"
	"go/build"
	"os"
	"os/exec"
	"path"
	"runtime"

	"github.com/checkmarx/2ms/reporting"
)

type cli struct {
	executable  string
	resultsPath string
}

func createCLI(outputDir string) (cli, error) {
	executable := path.Join(outputDir, "2ms")
	lib, err := build.Import("github.com/checkmarx/2ms", "", build.FindOnly)
	if err != nil {
		return cli{}, fmt.Errorf("failed to import 2ms: %s", err)
	}

	cmd := exec.Command("go", "build", "-o", executable, lib.ImportPath)
	cmd.Env = append(os.Environ(), fmt.Sprintf("GOOS=%s", runtime.GOOS), fmt.Sprintf("GOARCH=%s", runtime.GOARCH))

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return cli{}, fmt.Errorf("failed to build 2ms: %s", err)
	}

	return cli{
			executable:  executable,
			resultsPath: path.Join(outputDir, "results.json"),
		},
		nil
}

func generateProject(outputDir string) error {
	token := "g" + "hp" + "_ixOl" + "iEFNK4O" + "brYB506" + "8oXFd" + "9JUF" + "iRy0RU" + "KNl"
	content := "bla bla bla\nGitHubToken: " + token + "\nbla bla bla"

	if err := os.WriteFile(path.Join(outputDir, "secret.txt"), []byte(content), 0644); err != nil {
		return err
	}

	return nil
}

func (c *cli) run(projectDir string, args ...string) error {
	argsWithDefault := append([]string{"filesystem", "--path", projectDir, "--report-path", c.resultsPath}, args...)
	cmd := exec.Command(c.executable, argsWithDefault...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (c *cli) getReport() (reporting.Report, error) {
	report := reporting.Init()

	content, err := os.ReadFile(c.resultsPath)
	if err != nil {
		return reporting.Report{}, err
	}
	if err := json.Unmarshal(content, &report); err != nil {
		return reporting.Report{}, err
	}

	return *report, nil
}
