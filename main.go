package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	_ "github.com/lib/pq"
)

type Config struct {
	Port        string
	HubURL      string
	DatabaseURL string
	BaseURL     string // public URL of this app, e.g. https://echo.app.openilink.com
}

type Installation struct {
	ID            string
	AppToken      string
	SigningSecret string
	BotID         string
	Handle        string
}

var (
	cfg Config
	db  *sql.DB
)

func main() {
	cfg = Config{
		Port:        envOr("PORT", "8081"),
		HubURL:      os.Getenv("HUB_URL"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
		BaseURL:     os.Getenv("BASE_URL"),
	}

	var err error
	db, err = sql.Open("postgres", cfg.DatabaseURL)
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
	mux.HandleFunc("POST /callback", handleCallback)
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
		signing_secret TEXT NOT NULL,
		bot_id TEXT NOT NULL,
		handle TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`)
	return err
}

// POST /callback — Hub notifies us after a user installs the app
func handleCallback(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InstallationID string `json:"installation_id"`
		AppToken       string `json:"app_token"`
		SigningSecret  string `json:"signing_secret"`
		BotID          string `json:"bot_id"`
		Handle         string `json:"handle"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	// Upsert installation
	_, err := db.Exec(`INSERT INTO installations (id, app_token, signing_secret, bot_id, handle)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (id) DO UPDATE SET app_token=$2, signing_secret=$3, bot_id=$4, handle=$5`,
		req.InstallationID, req.AppToken, req.SigningSecret, req.BotID, req.Handle)
	if err != nil {
		slog.Error("save installation failed", "err", err)
		http.Error(w, "save failed", http.StatusInternalServerError)
		return
	}

	slog.Info("installation saved", "id", req.InstallationID, "bot", req.BotID, "handle", req.Handle)

	// Return our webhook URL so Hub auto-sets request_url
	w.Header().Set("Content-Type", "application/json")
	requestURL := cfg.BaseURL + "/hub/webhook"
	json.NewEncoder(w).Encode(map[string]string{"request_url": requestURL})
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
		"scopes":      []string{"messages.send"},
		"redirect_url": cfg.BaseURL + "/callback",
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
	expected := computeSignature(inst.SigningSecret, timestamp, body)
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
	req, _ := http.NewRequest("POST", cfg.HubURL+"/bot/v1/messages/send", bytes.NewReader(payload))
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
	err := db.QueryRow("SELECT id, app_token, signing_secret, bot_id, handle FROM installations WHERE id=$1", id).
		Scan(&inst.ID, &inst.AppToken, &inst.SigningSecret, &inst.BotID, &inst.Handle)
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
