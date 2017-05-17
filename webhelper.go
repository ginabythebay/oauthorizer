package oauthorizer

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"golang.org/x/net/context"

	"golang.org/x/oauth2"
)

// RedirectError is a type of error that can be handled by redirecting
// a client to a url.
type RedirectError interface {
	error
	GetURL() string
}

type needsAuth struct {
	URL string
}

func (na needsAuth) Error() string {
	return fmt.Sprintf("needs authentication error: %s", na.URL)
}

func (na needsAuth) GetURL() string {
	return na.URL
}

// WebHelper helps to navigate through the oauth2 process.  Typically
// you would call GetClient before needing to access a resource.  If
// there it returns nil, you could call GenAuthURL and redirect the
// browser to that.
//
// If the users grants access to the resource, the browser will be
// redirected to the url listed in the Config.  In that handler, you
// can call Exchange and if it succeeds, you can redirect back to the
// handler that needs to access the resource.
//
// Below is a sketch that demonstrates an expected use-case.
//
//   func HandleMain(w http.ResponseWriter, r *http.Request) {
//       ctx := r.Context()
//       webHelper := getWebHelper()
//
//   	 client := webHelper.GetClient(ctx)
//   	 if client == nil {
//   		 url, err := webHelper.GenAuthURL(ctx)
//           if err != nil {
//      	     writeError(w, http.StatusInternalServerError)
//      	     return
//               }
//   		 http.Redirect(w, r, url, http.StatusTemporaryRedirect)
//   		 return
//   	 }
//
//       // use client to access our resource
//   }
//
//   func HandleOauthCallback(w http.ResponseWriter, r *http.Request) {
//       ctx := r.Context()
//       webHelper := getWebHelper()
//
//       if err = oh.Exchange(ctx, r); err != nil {
//      	 writeError(w, http.StatusInternalServerError)
//      	 return
//       }
//
//       http.Redirect(w, r, urlOfMainHandler, http.StatusTemporaryRedirect)
//   }
type WebHelper struct {
	Config *oauth2.Config
	// Knows how to store and retrieve temporary values that is used
	// for the oauth2 state parameter.  There will be an active nonce
	// for each in-flight authorization request.  It is ok to delete
	// the nonce after authorization finishes (succeeds or fails).
	// This library never deletes a nonce, but will overwrite the last
	// one whenever we restart authorization.  Required.
	NonceStore Storer

	// Knows how to store and retrieve oauth2 tokens.  Currently these
	// are only written once, after authorization succeeds.  Required.
	TokenStore Storer

	// Optional way to configure the authorization url used to start
	// the authorization flow.
	Opts []oauth2.AuthCodeOption
}

// GetClient returns an http client configured for oauth2.  Returns
// nil if there isn't a valid token found.
func (wh *WebHelper) GetClient(ctx context.Context) *http.Client {
	tok := restoreToken(ctx, wh.TokenStore)
	if tok == nil {
		return nil
	}
	return wh.Config.Client(ctx, tok)
}

// GenAuthURL Generates a new authorization URL.  Note that this has
// the side effect of saving the associated nonce.
func (wh *WebHelper) GenAuthURL(ctx context.Context) (string, error) {
	nonce := newNonce()
	url := wh.Config.AuthCodeURL(nonce, wh.Opts...)
	if err := wh.NonceStore.Save(ctx, []byte(nonce)); err != nil {
		return "", err
	}
	return url, nil
}

// Exchange exchanges an authorization code for a token, after
// verifying the state is the same we previously saved.  If this
// returns without an error, you can call GetClient to get a client with
// the token configured.
func (wh *WebHelper) Exchange(ctx context.Context, r *http.Request) error {
	b, err := wh.NonceStore.Restore(ctx)
	if err != nil {
		return fmt.Errorf("unable to load nonce: %v", err)
	}
	nonce := string(b)

	state := r.FormValue("state")
	if state != nonce {
		return fmt.Errorf("expected %q for state but got %q", nonce, state)
	}

	code := r.FormValue("code")
	tok, err := wh.Config.Exchange(ctx, code)
	if err != nil {
		return fmt.Errorf("code exchange failure: %v", err)
	}

	if err = saveToken(ctx, wh.TokenStore, tok); err != nil {
		return fmt.Errorf("token save failure: %v", err)
	}
	return nil
}

func newNonce() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, 16)
	_, _ = r.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}
