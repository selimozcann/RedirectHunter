package output

import (
	"bufio"
	"encoding/json"
	"io"

	"github.com/selimozcann/RedirectHunter/internal/model"
)

// JSONLWriter writes Result objects as JSON Lines.
type JSONLWriter struct {
	w *bufio.Writer
}

// NewJSONLWriter creates a new writer.
func NewJSONLWriter(w io.Writer) *JSONLWriter {
	return &JSONLWriter{w: bufio.NewWriter(w)}
}

// WriteResult writes a single result.
func (j *JSONLWriter) WriteResult(res model.Result) error {
	enc := json.NewEncoder(j.w)
	if err := enc.Encode(res); err != nil {
		return err
	}
	return j.w.Flush()
}
