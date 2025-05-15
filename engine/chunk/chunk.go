package chunk

//go:generate mockgen -source=$GOFILE -destination=${GOPACKAGE}_mock.go -package=${GOPACKAGE}

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
	"unicode"

	"github.com/h2non/filetype"
)

const (
	defaultSize          = 100 * 1024      // 100Kib
	defaultMaxPeekSize   = 25 * 1024       // 25Kib
	defaultFileThreshold = 1 * 1024 * 1024 // 1MiB
)

var ErrUnsupportedFileType = errors.New("unsupported file type")

type Chunk struct {
	BufPool            *sync.Pool
	PeekBufPool        *sync.Pool
	Size               int
	MaxPeekSize        int
	SmallFileThreshold int64
}

type IChunk interface {
	GetBuf() (*[]byte, bool)
	PutBuf(buf *[]byte)
	GetPeekBuf(buf []byte) (*bytes.Buffer, bool)
	PutPeekBuf(buf *bytes.Buffer)
	GetSize() int
	GetMaxPeekSize() int
	GetFileThreshold() int64
	ReadChunk(reader *bufio.Reader, totalLines int) (string, error)
}

func NewChunk() *Chunk {
	return NewChunkWithSize(defaultSize, defaultMaxPeekSize, defaultFileThreshold)
}

func NewChunkWithSize(size, maxPeekSize, smallFileThreshold int) *Chunk {
	return &Chunk{
		BufPool: &sync.Pool{
			New: func() interface{} {
				b := make([]byte, size)
				return &b
			},
		},
		PeekBufPool: &sync.Pool{
			New: func() interface{} {
				// pre-allocate enough capacity for initial chunk + peek
				return bytes.NewBuffer(make([]byte, 0, size+maxPeekSize))
			},
		},
		Size:               size,
		MaxPeekSize:        maxPeekSize,
		SmallFileThreshold: int64(smallFileThreshold),
	}
}

func (c *Chunk) GetBuf() (*[]byte, bool) {
	buf, ok := c.BufPool.Get().(*[]byte)
	return buf, ok
}

func (c *Chunk) PutBuf(buf *[]byte) {
	c.BufPool.Put(buf)
}

func (c *Chunk) GetPeekBuf(buf []byte) (*bytes.Buffer, bool) {
	peekBuf, ok := c.PeekBufPool.Get().(*bytes.Buffer)
	peekBuf.Reset()
	peekBuf.Write(buf) // seed with buf
	return peekBuf, ok
}

func (c *Chunk) PutPeekBuf(buf *bytes.Buffer) {
	c.PeekBufPool.Put(buf)
}

func (c *Chunk) GetSize() int {
	return c.Size
}

func (c *Chunk) GetMaxPeekSize() int {
	return c.MaxPeekSize
}

func (c *Chunk) GetFileThreshold() int64 {
	return c.SmallFileThreshold
}

// ReadChunk reads the next chunk of data from file
func (c *Chunk) ReadChunk(reader *bufio.Reader, totalLines int) (string, error) {
	chunk, ok := c.GetBuf()
	if !ok {
		return "", fmt.Errorf("expected *[]byte, got %T", chunk)
	}
	defer c.PutBuf(chunk)

	n, err := reader.Read(*chunk)
	var chunkStr string
	// "Callers should always process the n > 0 bytes returned before considering the error err."
	// https://pkg.go.dev/io#Reader
	if n > 0 {
		// only check the filetype at the start of file
		if totalLines == 0 && ShouldSkipFile((*chunk)[:n]) {
			return "", fmt.Errorf("skipping file: %w", ErrUnsupportedFileType)
		}

		chunkStr, err = c.processChunk(reader, (*chunk)[:n])
		if err != nil {
			return "", err
		}
	}
	if err != nil {
		return "", err
	}
	return chunkStr, nil
}

// processChunk processes the chunk, reading until a safe boundary
func (c *Chunk) processChunk(reader *bufio.Reader, chunk []byte) (string, error) {
	peekBuf, ok := c.GetPeekBuf(chunk)
	if !ok {
		return "", fmt.Errorf("expected *bytes.Buffer, got %T", peekBuf)
	}
	defer c.PutPeekBuf(peekBuf)

	if readErr := c.readUntilSafeBoundary(reader, len(chunk), peekBuf); readErr != nil {
		return "", fmt.Errorf("failed to read until safe boundary for file: %w", readErr)
	}

	return peekBuf.String(), nil
}

// readUntilSafeBoundary (hopefully) avoids splitting (https://github.com/gitleaks/gitleaks/issues/1651)
func (c *Chunk) readUntilSafeBoundary(r *bufio.Reader, n int, peekBuf *bytes.Buffer) error {
	if peekBuf.Len() == 0 {
		return nil
	}

	// keep reading until see our “\n…\n” boundary or hit limits
	for peekBuf.Len()-n < c.MaxPeekSize {
		if endsWithTwoNewlines(peekBuf.Bytes()) {
			return nil
		}

		b, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("failed to read byte: %w", err)
		}
		peekBuf.WriteByte(b)
	}

	return nil
}

// endsWithTwoNewlines returns true if b ends in at least two '\n's (ignoring any number of ' ', '\r', or '\t' between them)
func endsWithTwoNewlines(b []byte) bool {
	count := 0
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == '\n' {
			count++
			if count >= 2 {
				return true
			}
		} else if unicode.IsSpace(rune(b[i])) {
			// the presence of other whitespace characters (`\r`, ` `, `\t`) shouldn't reset the count
			continue
		} else {
			return false
		}
	}
	return false
}

// ShouldSkipFile checks if the file should be skipped based on its content type
func ShouldSkipFile(data []byte) bool {
	// TODO: could other optimizations be introduced here?
	mimetype, err := filetype.Match(data)
	if err != nil {
		return true // could not determine file type
	}
	return mimetype.MIME.Type == "application" // skip binary files
}
