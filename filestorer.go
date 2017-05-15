package oauthorizer

import (
	"io/ioutil"

	"golang.org/x/net/context"
)

// FileStorer knows how to save/restore bytes to/from a file.  It is a
// good choice to use this with GetCLIClient.
type FileStorer struct {
	Filename string
}

// Save saves bytes to the associated file
func (fs FileStorer) Save(ctx context.Context, b []byte) (err error) {
	return ioutil.WriteFile(fs.Filename, b, 0666)
}

// Restore loads bytes from the associated file
func (fs FileStorer) Restore(ctx context.Context) ([]byte, error) {
	return ioutil.ReadFile(fs.Filename)
}
