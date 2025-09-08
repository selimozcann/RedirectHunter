package output

import (
	"bufio"
	"encoding/json"
	"io"
	"sync"

	"github.com/selimozcann/RedirectHunter/internal/model"
)

// JSONLWriter writes one Result per line as JSON.
type JSONLWriter struct {
	w  *bufio.Writer
	mu sync.Mutex
}

// NewJSONLWriter wraps an io.Writer with buffering.
func NewJSONLWriter(w io.Writer) *JSONLWriter {
	return &JSONLWriter{w: bufio.NewWriter(w)}
}

// Write writes a single result as a JSON line.
func (j *JSONLWriter) Write(r model.Result) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	enc := json.NewEncoder(j.w)
	// For stable lines without extra spaces.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return err
	}
	return nil
}

// Flush flushes the underlying buffer.
func (j *JSONLWriter) Flush() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.w.Flush()
}

// Close flushes the buffer; keep the signature similar to io.Closer.
func (j *JSONLWriter) Close() error {
	return j.Flush()
}
