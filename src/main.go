package main

import (
	"flag"
	"fmt"
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
	nrasURL := fs.String("nvidia-nras-url", envOrDefault("NVIDIA_NRAS_URL", ""),
		"NVIDIA NRAS endpoint for GPU attestation verification (env: NVIDIA_NRAS_URL)")
	listen := fs.String("listen", envOrDefault("LISTEN_ADDR", ":8080"),
		"Listen address (env: LISTEN_ADDR)")

	if err := fs.Parse(os.Args[1:]); err != nil {
		logFatal("flag parse failed", "error", err)
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

	// Set NVIDIA NRAS URL for GPU attestation verification.
	if *nrasURL != "" {
		nvidiaVerifierURL = *nrasURL
	}
	if err != nil {
		logFatal("failed to create OIDC verifier", "error", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthzHandler)
	mux.HandleFunc("GET /metrics", metricsHandler)
	mux.HandleFunc("POST /", requireAuth(verifyHandler, verifier))

	logInfo("attestation server starting",
		"oidc_issuer", *oidcIssuer,
		"oidc_audience", *oidcAudience,
		"client_role", *oidcClientRole,
		"listen", *listen,
	)
	logFatal("http server exited", "error", http.ListenAndServe(*listen, mux))
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// healthzHandler returns 200 OK for load balancer probes.
func healthzHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}
