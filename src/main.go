package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	fs := flag.NewFlagSet("attestation-server", flag.ExitOnError)

	oidcIssuer := fs.String("oidc-issuer", envOrDefault("OIDC_ISSUER", ""),
		"OIDC issuer URL for bearer token verification (required, env: OIDC_ISSUER)")
	oidcAudience := fs.String("oidc-audience", envOrDefault("OIDC_AUDIENCE", "attestation-server"),
		"Expected OIDC audience claim (env: OIDC_AUDIENCE)")
	oidcClientRole := fs.String("oidc-client-role", envOrDefault("OIDC_CLIENT_ROLE", "attestation-server:client"),
		"OIDC role required for verification requests (env: OIDC_CLIENT_ROLE)")
	oidcRoleClaim := fs.String("oidc-role-claim", envOrDefault("OIDC_ROLE_CLAIM", "urn:zitadel:iam:org:project:roles"),
		"JWT claim key containing roles (env: OIDC_ROLE_CLAIM)")
	listen := fs.String("listen", envOrDefault("LISTEN_ADDR", ":8080"),
		"Listen address (env: LISTEN_ADDR)")

	if err := fs.Parse(os.Args[1:]); err != nil {
		log.Fatal(err)
	}

	if *oidcIssuer == "" {
		fmt.Fprintln(os.Stderr, "error: --oidc-issuer (or OIDC_ISSUER env) is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	verifier, err := NewOIDCVerifier(&OIDCConfig{
		Issuer:     *oidcIssuer,
		Audience:   *oidcAudience,
		ClientRole: *oidcClientRole,
		RoleClaim:  *oidcRoleClaim,
	})
	if err != nil {
		log.Fatalf("Failed to create OIDC verifier: %v", err)
	}

	http.HandleFunc("/", requireAuth(verifyHandler, verifier))

	fmt.Println("--- Privasys Attestation Server ---")
	fmt.Printf("OIDC issuer : %s\n", *oidcIssuer)
	fmt.Printf("OIDC audience: %s\n", *oidcAudience)
	fmt.Printf("Client role  : %s\n", *oidcClientRole)
	fmt.Printf("Listening on %s\n", *listen)
	fmt.Println("Endpoint:")
	fmt.Println("  POST /  (Bearer token, role: attestation-server:client)")
	log.Fatal(http.ListenAndServe(*listen, nil))
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
