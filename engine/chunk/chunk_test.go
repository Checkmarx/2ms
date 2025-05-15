package chunk

import (
	"bufio"
	"bytes"
	"github.com/stretchr/testify/require"
	"io"
	"strings"
	"testing"
)

func TestGetAndPutBuf(t *testing.T) {
	chunk := NewChunk()
	buf, ok := chunk.GetBuf()
	defer chunk.PutBuf(buf)

	require.True(t, ok)
	require.Equal(t, defaultSize, len(*buf))
}

func TestGetAndPutPeekBuf(t *testing.T) {
	chunk := NewChunk()
	data := []byte("test")
	buf, ok := chunk.GetPeekBuf(data)
	defer chunk.PutPeekBuf(buf)

	require.True(t, ok)
	require.Equal(t, defaultSize+defaultMaxPeekSize, buf.Cap())
	require.Equal(t, string(data), buf.String())
}

func TestGetSize(t *testing.T) {
	chunk := NewChunk()
	require.Equal(t, defaultSize, chunk.GetSize())
}

func TestGetMaxPeekSize(t *testing.T) {
	chunk := NewChunk()
	require.Equal(t, defaultMaxPeekSize, chunk.GetMaxPeekSize())
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
			expected: "abc\ndef\nghi\njkl\nmno\npqr\ns",
		},
		{
			name:     "successful read - multiple lines with consecutives new lines",
			reader:   strings.NewReader("abc\ndef\n\nghi\n"),
			expected: "abc\ndef\n\n",
		},
		{
			name:     "multiple lines without consecutives new lines",
			reader:   strings.NewReader("abc\ndef\nghi\n"),
			expected: "abc\ndef\nghi\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			chunk := NewChunkWithSize(5, 20, 20)
			reader := bufio.NewReader(tc.reader)

			// Act
			result, err := chunk.ReadChunk(reader, 0)
			require.ErrorIs(t, err, tc.expectedError)

			// Assert
			require.Equal(t, tc.expected, result)
		})
	}
}

func TestReadUntilSafeBoundary(t *testing.T) {
	// Arrange
	testCases := []struct {
		name     string
		reader   io.Reader
		expected string
	}{
		// Current split is fine, exit early.
		{
			name:     "safe original split - LF",
			reader:   strings.NewReader("abc\n\ndefghijklmnop\n\nqrstuvwxyz"),
			expected: "abc\n\n",
		},
		{
			name:     "safe original split - CRLF",
			reader:   strings.NewReader("a\r\n\r\nbcdefghijklmnop\n"),
			expected: "a\r\n\r\n",
		},
		// Current split is bad, look for a better one.
		{
			name:     "safe split - LF",
			reader:   strings.NewReader("abcdefg\nhijklmnop\n\nqrstuvwxyz"),
			expected: "abcdefg\nhijklmnop\n\n",
		},
		{
			name:     "safe split - CRLF",
			reader:   strings.NewReader("abcdefg\r\nhijklmnop\r\n\r\nqrstuvwxyz"),
			expected: "abcdefg\r\nhijklmnop\r\n\r\n",
		},
		{
			name:     "safe split - blank line",
			reader:   strings.NewReader("abcdefg\nhijklmnop\n\t  \t\nqrstuvwxyz"),
			expected: "abcdefg\nhijklmnop\n\t  \t\n",
		},
		// Current split is bad, exhaust options.
		{
			name:     "no safe split",
			reader:   strings.NewReader("abcdefg\nhijklmnopqrstuvwxyz"),
			expected: "abcdefg\nhijklmnopqrstuvwx",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, 5)
			n, err := tc.reader.Read(buf)
			require.NoError(t, err)

			// Act
			chunk := NewChunkWithSize(5, 20, 20)
			reader := bufio.NewReader(tc.reader)
			peekBuf := bytes.NewBuffer(buf[:n])
			err = chunk.readUntilSafeBoundary(reader, n, peekBuf)
			require.NoError(t, err)

			// Assert
			require.Equal(t, tc.expected, peekBuf.String())
		})
	}
}
