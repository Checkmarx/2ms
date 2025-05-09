package utils

import (
	"encoding/json"
	"fmt"
	"strings"
)

// normalizeReportData recursively traverses the report data and removes any carriage return characters.
// Fixed version that handles circular references safely
func NormalizeReportData(data interface{}) (interface{}, error) {
	fmt.Println("About to call the safe normalizeReportData which it will tell you about the circular structure...")
	bytes, err := json.Marshal(data)
	if err != nil {

		return nil, fmt.Errorf("failed to marshal data: %w", err)
	}

	jsonStr := string(bytes)
	jsonStr = strings.ReplaceAll(jsonStr, "\\r", "")

	// Unmarshal back to a Go data structure
	var result interface{}
	err = json.Unmarshal([]byte(jsonStr), &result)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal data: %w", err)
	}

	return result, nil
}
