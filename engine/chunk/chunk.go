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

type Option func(*Chunk)

// WithSize sets the chunk size
func WithSize(size int) Option {
	return func(args *Chunk) {
		args.size = size
	}
}

// WithMaxPeekSize sets the max size of look-ahead bytes
func WithMaxPeekSize(maxPeekSize int) Option {
	return func(args *Chunk) {
		args.maxPeekSize = maxPeekSize
	}
}

// WithSmallFileThreshold sets the threshold for small files
func WithSmallFileThreshold(smallFileThreshold int64) Option {
	return func(args *Chunk) {
		args.smallFileThreshold = smallFileThreshold
	}
}

// Chunk holds two pools and sizing parameters needed for reading chunks of data with look-ahead
type Chunk struct {
	bufPool            *sync.Pool // *bytes.Buffer with cap Size + MaxPeekSize
	peekedBufPool      *sync.Pool // *[]byte slices of length Size + MaxPeekSize
	size               int        // base chunk size
	maxPeekSize        int        // max size of look-ahead bytes
	smallFileThreshold int64      // files smaller than this skip chunking
}

type IChunk interface {
	GetSize() int
	GetMaxPeekSize() int
	GetFileThreshold() int64
	ReadChunk(reader *bufio.Reader, totalLines int) (string, error)
}

func New(opts ...Option) *Chunk {
	// set default options
	c := &Chunk{
		size:               defaultSize,
		maxPeekSize:        defaultMaxPeekSize,
		smallFileThreshold: defaultFileThreshold,
	}
	// apply overrides
	for _, opt := range opts {
		opt(c)
	}
	c.bufPool = &sync.Pool{
		New: func() interface{} {
			// pre-allocate dynamic-size buffer for reading chunks (up to chunk size + peek size)
			return bytes.NewBuffer(make([]byte, 0, c.size+c.maxPeekSize))
		},
	}
	c.peekedBufPool = &sync.Pool{
		New: func() interface{} {
			// pre-allocate fixed-size block for loading chunks
			b := make([]byte, c.size+c.maxPeekSize)
			return &b
		},
	}
	return c
}

// GetBuf returns a bytes.Buffer from the pool, seeded with the data
func (c *Chunk) GetBuf(data []byte) (*bytes.Buffer, bool) {
	window, ok := c.bufPool.Get().(*bytes.Buffer)
	if !ok {
		return nil, false
	}
	window.Reset()
	window.Write(data) // seed the buffer with the data
	return window, ok
}

// PutBuf returns the bytes.Buffer to the pool
func (c *Chunk) PutBuf(window *bytes.Buffer) {
	window.Reset()
	c.bufPool.Put(window)
}

// GetPeekedBuf returns a fixed-size []byte from the pool
func (c *Chunk) GetPeekedBuf() (*[]byte, bool) {
	b, ok := c.peekedBufPool.Get().(*[]byte)
	return b, ok
}

// PutPeekedBuf returns the fixed-size []byte to the pool
func (c *Chunk) PutPeekedBuf(b *[]byte) {
	c.peekedBufPool.Put(b)
}

func (c *Chunk) GetSize() int {
	return c.size
}

func (c *Chunk) GetMaxPeekSize() int {
	return c.maxPeekSize
}

func (c *Chunk) GetFileThreshold() int64 {
	return c.smallFileThreshold
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
