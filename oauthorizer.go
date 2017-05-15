/*
Package oauthorizer helps implement the client side of the oauth2
authorization flow.  This package has only been tested against google
endpoints (e.g. Google Calendar)


*/
package oauthorizer

import (
	"encoding/json"
	"fmt"

	"golang.org/x/net/context"

	"golang.org/x/oauth2"
)

// Storer knows how to save/restore byte slices
type Storer interface {
	Save(ctx context.Context, b []byte) error
	Restore(ctx context.Context) ([]byte, error)
}

func saveToken(ctx context.Context, ts Storer, tok *oauth2.Token) error {
	b, err := json.Marshal(tok)
	if err != nil {
		return fmt.Errorf("unable to marshal token: %v", err)
	}
	return ts.Save(ctx, b)
}

func restoreToken(ctx context.Context, ts Storer) *oauth2.Token {
	b, err := ts.Restore(ctx)
	if err != nil {
		return nil
	}

	var tok oauth2.Token
	if err = json.Unmarshal(b, &tok); err != nil {
		return nil
	}

	return &tok
}
