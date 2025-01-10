package linecontent

const (
	contextLeftSizeLimit  = 250
	contextRightSizeLimit = 250
)

func GetLineContent(lineContent string, startColumn, endColumn int) string {
	lineContentSize := len(lineContent)

	startIndex := startColumn - contextLeftSizeLimit
	if startIndex < 0 {
		startIndex = 0
	}

	endIndex := endColumn + contextRightSizeLimit
	if endIndex > lineContentSize {
		endIndex = lineContentSize
	}

	return lineContent[startIndex:endIndex]
}
