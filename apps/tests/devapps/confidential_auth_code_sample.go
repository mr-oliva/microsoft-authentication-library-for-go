// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

var (
	accessToken        string
	confidentialConfig = CreateConfig("confidential_config.json")
	app                confidential.Client
	account            confidential.Account
)

// TODO(msal): I'm not sure what to do here with the CodeChallenge and State. authCodeURLParams
// is no more.  CodeChallenge is only used now in a confidential.AcquireTokenByAuthCode(), which
// this is not using.  Maybe now this is a two step process????
func redirectToURLConfidential(w http.ResponseWriter, r *http.Request) {
	result, err := app.AcquireTokenSilent(r.Context(), confidentialConfig.Scopes, confidential.WithSilentAccount(account))
	if err == nil {
		accessToken = result.AccessToken
		fmt.Fprintln(w, "[Non-Interactive] Access token is "+accessToken)
		return
	}
	if err.Error() != "no token found" {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	authURL, err := app.AuthCodeURL(r.Context(), confidentialConfig.ClientID, confidentialConfig.RedirectURI, confidentialConfig.Scopes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	// Redirecting to the URL we have received
	log.Println("redirecting to auth: ", authURL)
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

func getTokenConfidential(w http.ResponseWriter, r *http.Request) {
	codes, ok := r.URL.Query()["code"]
	if !ok || len(codes[0]) < 1 {
		fmt.Fprintln(w, errors.New("Authorization code missing"))
		log.Fatal(errors.New("Authorization code missing"))
		return
	}
	code := codes[0]
	// Getting the access token using the authorization code
	result, err := app.AcquireTokenByAuthCode(
		context.Background(),
		code,
		confidentialConfig.RedirectURI,
		confidentialConfig.Scopes,
	)
	if err != nil {
		fmt.Fprintln(w, err.Error())
		log.Fatal(err)
		return
	}
	account = result.Account
	// Prints the access token on the webpage
	accessToken = result.AccessToken
	fmt.Fprintln(w, "[Interactive] Access token is "+accessToken)
}

func acquireByAuthorizationCodeConfidential() {
	cred, err := confidential.NewCredFromSecret(confidentialConfig.ClientSecret)
	if err != nil {
		log.Fatal(err)
	}
	options := confidential.WithCache(cacheAccessor)
	app, err = confidential.New(confidentialConfig.Authority, confidentialConfig.ClientID, cred, options)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", redirectToURLConfidential)
	// The redirect uri set in our app's registration is http://localhost:port/redirect
	http.HandleFunc("/redirect", getTokenConfidential)
	port := "8080"
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}
