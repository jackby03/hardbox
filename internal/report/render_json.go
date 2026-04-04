package report

import (
	"encoding/json"
	"io"
)

func renderJSON(v any, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
