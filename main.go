package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"
)

// Config from environment variables.
type Config struct {
	Port         string // PORT, default 8081
	HubURL       string // HUB_URL, e.g. https://hub.example.com
	AppToken     string // HUB_APP_TOKEN (from installation)
	SigningSecret string // HUB_SIGNING_SECRET (from installation)
}

func loadConfig() Config {
	cfg := Config{
		Port:         os.Getenv("PORT"),
		HubURL:       os.Getenv("HUB_URL"),
		AppToken:     os.Getenv("HUB_APP_TOKEN"),
		SigningSecret: os.Getenv("HUB_SIGNING_SECRET"),
	}
	if cfg.Port == "" {
		cfg.Port = "8081"
	}
	return cfg
}

var cfg Config

func main() {
	cfg = loadConfig()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /hub/webhook", handleHubWebhook)
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

	// Verify signature
	if cfg.SigningSecret != "" {
		timestamp := r.Header.Get("X-Timestamp")
		signature := r.Header.Get("X-Signature")
		expected := computeSignature(cfg.SigningSecret, timestamp, body)
		if signature != "sha256="+expected {
			slog.Warn("invalid signature", "expected", expected, "got", signature)
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
	}

	var event HubEvent
	if err := json.Unmarshal(body, &event); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	slog.Info("received event", "type", event.Type, "event_type", event.Event.Type,
		"trace_id", event.TraceID)

	// Handle URL verification
	if event.Type == "url_verification" {
		var challenge struct {
			Challenge string `json:"challenge"`
		}
		json.Unmarshal(body, &challenge)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"challenge": challenge.Challenge})
		return
	}

	// Handle command
	if event.Type == "command" {
		handleCommand(w, event)
		return
	}

	// Handle message event
	if event.Event.Type != "" {
		handleMessage(w, event)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func handleCommand(w http.ResponseWriter, event HubEvent) {
	data := event.Event.Data
	command, _ := data["command"].(string)
	text, _ := data["text"].(string)
	sender, _ := data["sender"].(map[string]any)
	senderID, _ := sender["id"].(string)

	slog.Info("command received", "command", command, "text", text, "sender", senderID)

	switch command {
	case "/echo":
		if text == "" {
			text = "(empty)"
		}
		// Sync reply
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"reply": fmt.Sprintf("Echo: %s", text),
		})

	case "/echo-delay":
		// Async reply after 5 seconds via Bot API
		go func() {
			time.Sleep(5 * time.Second)
			err := sendMessage(senderID, fmt.Sprintf("Delayed echo (5s): %s", text), event.TraceID)
			if err != nil {
				slog.Error("delayed send failed", "err", err)
			}
		}()
		// Immediate ack
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"reply": "收到，5 秒后回复...",
		})

	case "/ping":
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"reply": "pong!",
		})

	default:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"reply": fmt.Sprintf("未知命令: %s\n支持: /echo, /echo-delay, /ping", command),
		})
	}
}

func handleMessage(w http.ResponseWriter, event HubEvent) {
	data := event.Event.Data
	content, _ := data["content"].(string)
	sender, _ := data["sender"].(map[string]any)
	senderID, _ := sender["id"].(string)

	slog.Info("message received", "type", event.Event.Type, "content", content, "sender", senderID)

	// Echo back the message
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"reply": fmt.Sprintf("Echo: %s", content),
	})
}

// sendMessage calls Hub Bot API to send a message.
func sendMessage(to, content, traceID string) error {
	if cfg.HubURL == "" || cfg.AppToken == "" {
		return fmt.Errorf("hub not configured")
	}

	payload, _ := json.Marshal(map[string]string{
		"to":       to,
		"type":     "text",
		"content":  content,
		"trace_id": traceID,
	})

	req, _ := http.NewRequest("POST", cfg.HubURL+"/bot/v1/messages/send", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.AppToken)
	if traceID != "" {
		req.Header.Set("X-Trace-Id", traceID)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("hub api error: %d %s", resp.StatusCode, string(body))
	}

	slog.Info("message sent via hub api", "to", to, "trace_id", traceID)
	return nil
}

func computeSignature(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + ":"))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
