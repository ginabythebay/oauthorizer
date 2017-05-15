package oauthorizer

import (
	"fmt"
	"net/http"

	"golang.org/x/net/context"

	"golang.org/x/oauth2"
)

// CLIGetClient returns an http client, configured for oauth2 access.
// If authorization was previously granted, the previously saved token
// will be used.  Otherwise the user will be asked via stdout to point
// their browser at a url to grant access.  After they grant access,
// they will be taken to a web page that gives them a code, which they
// can then paste into stdin.
func CLIGetClient(ctx context.Context, config *oauth2.Config, ts Storer) (*http.Client, error) {
	tok := restoreToken(ctx, ts)
	if tok == nil {
		var err error
		if tok, err = authorize(ctx, config); err != nil {
			return nil, fmt.Errorf("failed authorization: %+v", err)
		}
		if err = saveToken(ctx, ts, tok); err != nil {
			return nil, fmt.Errorf("failed to save token: %+v", err)
		}
	}
	return config.Client(ctx, tok), nil
}

func authorize(ctx context.Context, config *oauth2.Config) (*oauth2.Token, error) {
	authURL := config.AuthCodeURL("unused_state_token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)

	var code string
	if _, err := fmt.Scan(&code); err != nil {
		return nil, fmt.Errorf("unable to read authorization code: %v", err)
	}

	tok, err := config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve token from authorization code: %v", err)
	}
	return tok, nil
}
