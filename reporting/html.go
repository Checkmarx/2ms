package reporting

import (
	"bytes"
	_ "embed"
	"html/template"
	"log"
)

var (
	//go:embed html/report.tmpl
	htmlTemplate string
	//go:embed html/report.css
	cssTemplate string
	//go:embed html/github.svg
	githubSVG string
	//go:embed html/checkmarx_logo.html
	checkmarxLogo string
)

func writeHtml(report Report) string {
	tmpl := template.Must(template.New("report").Funcs(getFuncMap()).Parse(htmlTemplate))
	var buffer bytes.Buffer
	err := tmpl.Execute(&buffer, report)
	if err != nil {
		log.Fatalf("failed to create HTML report with error: %v", err)
	}
	return buffer.String()
}

func getFuncMap() template.FuncMap {
	return template.FuncMap{
		"includeCSS":  func() template.CSS { return template.CSS(cssTemplate) },
		"includeSVG":  func() template.HTML { return template.HTML(githubSVG) },
		"includeLogo": func() template.HTML { return template.HTML(checkmarxLogo) },
	}
}
