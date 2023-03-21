package wrapper

import (
	"encoding/csv"
	"github.com/checkmarx/2ms/plugins"
	"github.com/stretchr/testify/require"
	"io"
	"os"
	"testing"
)

func TestWrapper_RunScans(t *testing.T) {
	// Load items
	csvFile, err := os.Open("../testdata/items.csv")
	if err != nil {
		t.Error(err)
	}
	csvReader := csv.NewReader(csvFile)

	items := make([]plugins.Item, 0)

	for {
		row, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Error(err)
		}
		item := ItemFromCSV(row)
		items = append(items, item)
	}

	w := NewWrapper()
	results := w.RunScans(items)

	require.NoError(t, err)
	require.Equal(t, len(results), 0)
}

func ItemFromCSV(row []string) plugins.Item {
	return plugins.Item{
		Content: row[0],
		Source:  row[1],
		ID:      row[2],
	}
}

func BenchmarkWrapper_RunScans(b *testing.B) {
	// Load items
	csvFile, err := os.Open("../testdata/items.csv")
	if err != nil {
		b.Error(err)
	}
	csvReader := csv.NewReader(csvFile)

	items := make([]plugins.Item, 0)

	for {
		row, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			b.Error(err)
		}
		item := ItemFromCSV(row)
		items = append(items, item)
	}

	w := NewWrapper()
	results := w.RunScans(items)

	require.NoError(b, err)
	require.Equal(b, len(results), 0)
}
