package chunk

import (
	"bufio"
	"bytes"
	"github.com/stretchr/testify/require"
	"io"
	"strings"
	"testing"
)

const (
	chunkSize          = 10
	maxPeekSize        = 5
	smallFileThreshold = int64(20)
)

func TestGetAndPutBuf(t *testing.T) {
	c := New()
	data := []byte("test")
	buf, ok := c.GetBuf(data)
	defer c.PutBuf(buf)

	require.True(t, ok)
	require.Equal(t, defaultSize+defaultMaxPeekSize, buf.Cap())
	require.Equal(t, string(data), buf.String())
}

func TestGetAndPutPeekedBuf(t *testing.T) {
	c := New()
	window, ok := c.GetPeekedBuf()
	defer c.PutPeekedBuf(window)

	require.True(t, ok)
	require.Equal(t, defaultSize+defaultMaxPeekSize, len(*window))
}

func TestGetSize(t *testing.T) {
	c := New()
	require.Equal(t, defaultSize, c.GetSize())
}

func TestGetMaxPeekSize(t *testing.T) {
	c := New()
	require.Equal(t, defaultMaxPeekSize, c.GetMaxPeekSize())
}

func TestReadChunk(t *testing.T) {
	// Arrange
	type testCase struct {
		name          string
		reader        io.Reader
		expected      string
		expectedError error
	}
	testCases := []testCase{
		{
			name:          "empty",
			reader:        strings.NewReader(""),
			expectedError: io.EOF,
		},
		{
			name:          "unsupported file type",
			reader:        bytes.NewReader([]byte{'P', 'K', 0x03, 0x04}),
			expectedError: ErrUnsupportedFileType,
		},
		{
			name:     "successful read",
			reader:   strings.NewReader("abc\n"),
			expected: "abc\n",
		},
		{
			name:     "successful read - peek size exceeded",
			reader:   strings.NewReader("abc\ndef\nghi\njkl\nmno\npqr\nstu\nvwx\nyz"),
			expected: "abc\ndef\nghi\njkl",
		},
		{
			name:     "successful read - multiple lines with consecutives new lines",
			reader:   strings.NewReader("abc\ndef\n\n\n\n\nghi\njkl"),
			expected: "abc\ndef\n\n\n",
		},
		{
			name:     "multiple lines without consecutives new lines",
			reader:   strings.NewReader("abc\ndef\nghi\n"),
			expected: "abc\ndef\nghi\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := New(WithSize(chunkSize), WithMaxPeekSize(maxPeekSize), WithSmallFileThreshold(smallFileThreshold))
			reader := bufio.NewReaderSize(tc.reader, chunkSize+maxPeekSize)

			// Act
			result, err := c.ReadChunk(reader, 0)
			require.ErrorIs(t, err, tc.expectedError)

			// Assert
			require.Equal(t, tc.expected, result)
		})
	}
}

func TestGenerateChunk(t *testing.T) {
	// Arrange
	testCases := []struct {
		name     string
		rawData  []byte
		expected string
	}{
		// Current split is fine, exit early.
		{
			name:     "safe original split - LF",
			rawData:  []byte("abc\ndef\n\n\nghijklmnop\n\nqrstuvwxyz"),
			expected: "abc\ndef\n\n\n",
		},
		{
			name:     "safe original split - CRLF",
			rawData:  []byte("abcdef\r\n\r\nghijklmnop\n"),
			expected: "abcdef\r\n\r\n",
		},
		// Current split is bad, look for a better one
		{
			name:     "safe split - LF",
			rawData:  []byte("abcdef\nghi\n\njklmnop\n\nqrstuvwxyz"),
			expected: "abcdef\nghi\n\n",
		},
		{
			name:     "safe split - CRLF",
			rawData:  []byte("abcdef\r\nghi\r\n\r\njklmnopqrstuvwxyz"),
			expected: "abcdef\r\nghi\r\n\r\n",
		},
		{
			name:     "safe split - blank line",
			rawData:  []byte("abcdefghi\n\t  \t\njklmnopqrstuvwxyz"),
			expected: "abcdefghi\n\t  \t\n",
		},
		// Current split is bad, exhaust options
		{
			name:     "no safe split",
			rawData:  []byte("abcdefg\nhijklmnopqrstuvwxyz"),
			expected: "abcdefg\nhijklmn",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := New(WithSize(chunkSize), WithMaxPeekSize(maxPeekSize), WithSmallFileThreshold(smallFileThreshold))
			reader := bufio.NewReaderSize(bytes.NewReader(tc.rawData), c.size+c.maxPeekSize)
			peekedBuf := make([]byte, c.size+c.maxPeekSize)
			_, err := reader.Read(peekedBuf)
			require.NoError(t, err)

			// Act
			chunkStr, err := c.generateChunk(peekedBuf)
			require.NoError(t, err)

			// Assert
			require.Equal(t, tc.expected, chunkStr)
		})
	}
}
