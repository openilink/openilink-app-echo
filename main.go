package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Config struct {
	Port    string
	HubURL  string
	DBPath  string // SQLite database file path
	BaseURL string // public URL of this app, e.g. https://echo.app.openilink.com
}

type Installation struct {
	ID            string
	AppToken      string
	WebhookSecret string
	BotID         string
}

type pkceState struct {
	Verifier string
	HubURL   string
	AppID    string
}

var (
	cfg Config
	db  *sql.DB

	// PKCE: temporary storage keyed by state
	pkceMu     sync.Mutex
	pkceStates = map[string]pkceState{}
)

func main() {
	cfg = Config{
		Port:    envOr("PORT", "8081"),
		HubURL:  os.Getenv("HUB_URL"),
		DBPath:  envOr("DB_PATH", "data/echo.db"),
		BaseURL: os.Getenv("BASE_URL"),
	}

	var err error
	db, err = sql.Open("sqlite3", cfg.DBPath)
	if err != nil {
		slog.Error("db open failed", "err", err)
		os.Exit(1)
	}
	if err := migrate(); err != nil {
		slog.Error("db migrate failed", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /hub/webhook", handleHubWebhook)
	mux.HandleFunc("GET /oauth/setup", handleOAuthSetup)
	mux.HandleFunc("GET /oauth/redirect", handleOAuthRedirect)
	mux.HandleFunc("GET /manifest.json", handleManifest)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	addr := ":" + cfg.Port
	slog.Info("echo app starting", "addr", addr, "hub", cfg.HubURL)
	if err := http.ListenAndServe(addr, mux); err != nil {
		slog.Error("server failed", "err", err)
		os.Exit(1)
	}
}

func migrate() error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS installations (
		id TEXT PRIMARY KEY,
		app_token TEXT NOT NULL,
		webhook_secret TEXT NOT NULL,
		bot_id TEXT NOT NULL,
		created_at TEXT NOT NULL DEFAULT (datetime('now'))
	)`)
	return err
}

// GET /oauth/setup — Hub redirects user here to start installation
// Query params: hub, app_id, bot_id, state
func handleOAuthSetup(w http.ResponseWriter, r *http.Request) {
	hubURL := r.URL.Query().Get("hub")
	appID := r.URL.Query().Get("app_id")
	botID := r.URL.Query().Get("bot_id")
	state := r.URL.Query().Get("state")

	if hubURL == "" || appID == "" || botID == "" || state == "" {
		http.Error(w, "missing required params", http.StatusBadRequest)
		return
	}

	// Generate PKCE code_verifier and code_challenge
	verifier := generateCodeVerifier()
	challenge := computeCodeChallenge(verifier)

	// Store verifier and context keyed by state
	pkceMu.Lock()
	pkceStates[state] = pkceState{Verifier: verifier, HubURL: hubURL, AppID: appID}
	pkceMu.Unlock()

	// Clean up after 10 minutes
	go func() {
		time.Sleep(10 * time.Minute)
		pkceMu.Lock()
		delete(pkceStates, state)
		pkceMu.Unlock()
	}()

	// Redirect to Hub's authorize endpoint
	authorizeURL := fmt.Sprintf("%s/api/apps/%s/oauth/authorize?bot_id=%s&state=%s&code_challenge=%s",
		hubURL, appID, botID, state, challenge)

	slog.Info("oauth setup", "app_id", appID, "bot_id", botID, "state", state)
	http.Redirect(w, r, authorizeURL, http.StatusFound)
}

// GET /oauth/redirect — Hub redirects back here after user authorizes
// Query params: code, state
func handleOAuthRedirect(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}

	// Retrieve and remove PKCE state
	pkceMu.Lock()
	ps, ok := pkceStates[state]
	delete(pkceStates, state)
	pkceMu.Unlock()

	if !ok {
		http.Error(w, "unknown or expired state", http.StatusBadRequest)
		return
	}

	// Exchange code for credentials
	exchangeURL := ps.HubURL + "/api/apps/" + ps.AppID + "/oauth/exchange"
	payload, _ := json.Marshal(map[string]string{
		"code":          code,
		"code_verifier": ps.Verifier,
	})

	resp, err := http.Post(exchangeURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		slog.Error("oauth exchange failed", "err", err)
		http.Error(w, "exchange failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		slog.Error("oauth exchange error", "status", resp.StatusCode, "body", string(b))
		http.Error(w, "exchange failed", http.StatusBadGateway)
		return
	}

	var creds struct {
		InstallationID string `json:"installation_id"`
		AppToken       string `json:"app_token"`
		WebhookSecret  string `json:"webhook_secret"`
		BotID          string `json:"bot_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&creds); err != nil {
		slog.Error("oauth exchange decode failed", "err", err)
		http.Error(w, "invalid exchange response", http.StatusBadGateway)
		return
	}

	// Upsert installation
	_, err = db.Exec(`INSERT INTO installations (id, app_token, webhook_secret, bot_id)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET app_token=excluded.app_token, webhook_secret=excluded.webhook_secret, bot_id=excluded.bot_id`,
		creds.InstallationID, creds.AppToken, creds.WebhookSecret, creds.BotID)
	if err != nil {
		slog.Error("save installation failed", "err", err)
		http.Error(w, "save failed", http.StatusInternalServerError)
		return
	}

	slog.Info("installation saved via oauth", "id", creds.InstallationID, "bot", creds.BotID)

	fmt.Fprintf(w, "Echo App installed successfully! You can close this page.")
}

// GET /manifest.json — App definition for Hub
func handleManifest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"slug":        "echo",
		"name":        "Echo",
		"description": "回显消息和命令的测试 App",
		"icon":        "🔊",
		"tools": []map[string]any{
			{"name": "echo", "description": "回显消息", "command": "echo", "parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"text": map[string]string{"type": "string", "description": "要回显的文本"},
				},
			}},
			{"name": "echo_delay", "description": "5秒后回显", "command": "echo-delay", "parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"text": map[string]string{"type": "string", "description": "要回显的文本"},
				},
			}},
			{"name": "ping", "description": "检查服务是否存活", "command": "ping"},
		},
		"events":      []string{"message.text"},
		"scopes":      []string{"message:write", "message:read"},
		"oauth_setup_url":    cfg.BaseURL + "/oauth/setup",
		"oauth_redirect_url": cfg.BaseURL + "/oauth/redirect",
		"webhook_url":        cfg.BaseURL + "/hub/webhook",
	})
}

// Hub event envelope
type HubEvent struct {
	V              int    `json:"v"`
	Type           string `json:"type"`
	TraceID        string `json:"trace_id"`
	InstallationID string `json:"installation_id"`
	Bot            struct {
		ID string `json:"id"`
	} `json:"bot"`
	Event struct {
		Type      string         `json:"type"`
		ID        string         `json:"id"`
		Timestamp int64          `json:"timestamp"`
		Data      map[string]any `json:"data"`
	} `json:"event"`
}

func handleHubWebhook(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)

	var event HubEvent
	if err := json.Unmarshal(body, &event); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	// URL verification — no signature check
	if event.Type == "url_verification" {
		var challenge struct{ Challenge string `json:"challenge"` }
		json.Unmarshal(body, &challenge)
		slog.Info("url verification", "challenge", challenge.Challenge)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"challenge": challenge.Challenge})
		return
	}

	// Look up installation for signature verification
	inst := getInstallation(event.InstallationID)
	if inst == nil {
		slog.Warn("unknown installation", "id", event.InstallationID)
		http.Error(w, "unknown installation", http.StatusUnauthorized)
		return
	}

	// Verify signature
	timestamp := r.Header.Get("X-Timestamp")
	signature := r.Header.Get("X-Signature")
	expected := computeSignature(inst.WebhookSecret, timestamp, body)
	if signature != "sha256="+expected {
		slog.Warn("invalid signature", "installation", inst.ID)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	slog.Info("received event", "type", event.Type, "event_type", event.Event.Type,
		"installation", inst.ID, "trace_id", event.TraceID)

	switch event.Event.Type {
	case "command":
		handleCommand(w, event, inst)
		return
	case "message.text", "message.image", "message.voice", "message.video", "message.file":
		handleMessage(w, event, inst)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func handleCommand(w http.ResponseWriter, event HubEvent, inst *Installation) {
	data := event.Event.Data
	command, _ := data["command"].(string)
	text, _ := data["text"].(string)
	args, _ := data["args"].(map[string]any)
	sender, _ := data["sender"].(map[string]any)
	senderID, _ := sender["id"].(string)

	slog.Info("command", "cmd", command, "text", text, "args", args,
		"sender", senderID, "trace_id", event.TraceID)

	// Helper: resolve a param from structured args first, then free-form text
	resolveText := func() string {
		if args != nil {
			if v, ok := args["text"].(string); ok && v != "" {
				return v
			}
		}
		return text
	}

	switch command {
	case "echo":
		t := resolveText()
		if t == "" {
			t = "(empty)"
		}
		jsonReply(w, fmt.Sprintf("Echo: %s", t))

	case "echo-delay":
		t := resolveText()
		go func() {
			time.Sleep(5 * time.Second)
			if err := sendMessage(inst, senderID, fmt.Sprintf("Delayed echo (5s): %s", t), event.TraceID); err != nil {
				slog.Error("delayed send failed", "err", err, "trace_id", event.TraceID)
			}
		}()
		jsonReply(w, "收到，5 秒后回复...")

	case "ping":
		jsonReply(w, "pong!")

	default:
		jsonReply(w, fmt.Sprintf("未知命令: %s\n支持: /echo, /echo-delay, /ping", command))
	}
}

func handleMessage(w http.ResponseWriter, event HubEvent, inst *Installation) {
	data := event.Event.Data
	content, _ := data["content"].(string)
	jsonReply(w, fmt.Sprintf("Echo: %s", content))
}

func jsonReply(w http.ResponseWriter, text string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"reply": text})
}

// sendMessage calls Hub Bot API using the installation's token.
func sendMessage(inst *Installation, to, content, traceID string) error {
	payload, _ := json.Marshal(map[string]string{
		"to": to, "type": "text", "content": content, "trace_id": traceID,
	})
	req, _ := http.NewRequest("POST", cfg.HubURL+"/bot/v1/message/send", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+inst.AppToken)
	if traceID != "" {
		req.Header.Set("X-Trace-Id", traceID)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("hub api: %d %s", resp.StatusCode, string(b))
	}
	return nil
}

func getInstallation(id string) *Installation {
	inst := &Installation{}
	err := db.QueryRow("SELECT id, app_token, webhook_secret, bot_id FROM installations WHERE id=?", id).
		Scan(&inst.ID, &inst.AppToken, &inst.WebhookSecret, &inst.BotID)
	if err != nil {
		return nil
	}
	return inst
}

func computeSignature(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + ":"))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// PKCE helpers

func generateCodeVerifier() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func computeCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
