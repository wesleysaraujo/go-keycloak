package main

import (
	"context"
	"encoding/json"
	oidc "github.com/coreos/go-oidc"
	uuid "github.com/google/uuid"
	"golang.org/x/oauth2"
	"log"
	"net/http"
)

var (
	clientID = "myclient"
	clientSecret =  "ae967994-d781-42f2-aa28-40852ebece67"
)

func main()  {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, "http://localhost:8080/auth/realms/myrealm")
	if err != nil {
		log.Fatalf(err.Error())
	}

	config := oauth2.Config{
		ClientID: clientID,
		ClientSecret: clientSecret,
		Endpoint: provider.Endpoint(),
		RedirectURL: "http://localhost:8081/auth/calback",
		Scopes: []string{oidc.ScopeOpenID, "profile", "email", "roles"},
	}

	state := uuid.New().String()

	// Redireciona para a página de Login do KeyCloak
	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, config.AuthCodeURL(state), http.StatusFound)
	})

	// Retorna o Token de Autorização
	http.HandleFunc("/auth/calback", func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("state") != state {
			http.Error(writer, "State inválido", http.StatusBadRequest)
			return
		}

		token, err := config.Exchange(ctx, request.URL.Query().Get("code"))
		if err != nil {
			http.Error(writer, "Falha ao trocar o token", http.StatusInternalServerError)
			return
		}

		// Resgata o idToken - O IDToken é utilizado para autenticação, enquanto o AccessToken é utilizado para autorização
		idToken, ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(writer, "Falha ao gerar o IDToken", http.StatusInternalServerError)
			return
		}

		userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err != nil {
			http.Error(writer, "Erro ao pegar UserInfo", http.StatusInternalServerError)
			return
		}

		response := struct {
			AccessToken *oauth2.Token
			IDToken string
			UserInfo *oidc.UserInfo
		}{
			token,
			idToken,
			userInfo,
		}

		data, err := json.Marshal(response)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		writer.Write(data)
	})

	log.Fatal(http.ListenAndServe(":8081", nil))
}
