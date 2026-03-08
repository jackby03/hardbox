package report

import (
	"encoding/json"
	"io"
)

func renderJSON(r *Report, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
