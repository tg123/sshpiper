// Package httpapi exposes the aggregator over HTTP and serves the embedded
// vanilla-JS web UI.
package httpapi

import (
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/cmd/sshpiperd-webadmin/internal/aggregator"
	"github.com/tg123/sshpiper/libadmin"
)

// Options configures the HTTP handler.
type Options struct {
	// AllowKill controls whether DELETE /api/v1/sessions/... is allowed.
	// Set to false for read-only deployments.
	AllowKill bool
	// Version is reported by /api/v1/version.
	Version string
	// StaticPath chooses where the browser UI is served from:
	//
	//   ""           — serve the embedded build (default)
	//   "disable"    — do not serve any UI; only /api/v1/* is exposed
	//   "<dir path>" — serve from the given directory on disk (useful
	//                  for `npm run watch` development against a live
	//                  daemon, or for shipping a forked frontend without
	//                  rebuilding the binary)
	StaticPath string
}

//go:embed web/index.html web/assets
//go:embed all:web/dist
var webFS embed.FS

// New returns an http.Handler exposing the admin API and embedded UI.
func New(agg *aggregator.Aggregator, opts Options) http.Handler {
	mux := http.NewServeMux()
	h := &handler{agg: agg, opts: opts}

	mux.HandleFunc("/api/v1/version", h.version)
	mux.HandleFunc("/api/v1/instances", h.instances)
	mux.HandleFunc("/api/v1/sessions", h.sessions)
	// /api/v1/sessions/{instance}/{id}                — DELETE
	// /api/v1/sessions/{instance}/{id}/stream         — GET (SSE)
	mux.HandleFunc("/api/v1/sessions/", h.sessionByID)

	switch opts.StaticPath {
	case "disable":
		log.Info("static UI is disabled (--web-static-path=disable); only /api/v1/* is exposed")
	case "":
		sub, err := fs.Sub(webFS, "web")
		if err == nil {
			mux.Handle("/", http.FileServer(http.FS(sub)))
		}
	default:
		log.Infof("serving static UI from disk: %s", opts.StaticPath)
		mux.Handle("/", http.FileServer(http.Dir(opts.StaticPath)))
	}
	return mux
}

type handler struct {
	agg  *aggregator.Aggregator
	opts Options
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (h *handler) version(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":    h.opts.Version,
		"allow_kill": h.opts.AllowKill,
	})
}

type instanceJSON struct {
	ID        string `json:"id"`
	Addr      string `json:"addr"`
	Version   string `json:"version,omitempty"`
	SSHAddr   string `json:"ssh_addr,omitempty"`
	StartedAt int64  `json:"started_at,omitempty"`
}

func (h *handler) instances(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	out := []instanceJSON{}
	for id, info := range h.agg.Instances() {
		out = append(out, instanceJSON{
			ID:        id,
			Addr:      info.Addr,
			Version:   info.Info.GetVersion(),
			SSHAddr:   info.Info.GetSshAddr(),
			StartedAt: info.Info.GetStartedAt(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"instances": out})
}

type sessionJSON struct {
	InstanceID     string `json:"instance_id"`
	InstanceAddr   string `json:"instance_addr"`
	ID             string `json:"id"`
	DownstreamUser string `json:"downstream_user"`
	DownstreamAddr string `json:"downstream_addr"`
	UpstreamUser   string `json:"upstream_user"`
	UpstreamAddr   string `json:"upstream_addr"`
	StartedAt      int64  `json:"started_at"`
	Streamable     bool   `json:"streamable"`
}

func (h *handler) sessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	all, errs := h.agg.ListAllSessions(ctx)
	out := make([]sessionJSON, 0, len(all))
	for _, s := range all {
		out = append(out, sessionJSON{
			InstanceID:     s.InstanceID,
			InstanceAddr:   s.InstanceAddr,
			ID:             s.Session.GetId(),
			DownstreamUser: s.Session.GetDownstreamUser(),
			DownstreamAddr: s.Session.GetDownstreamAddr(),
			UpstreamUser:   s.Session.GetUpstreamUser(),
			UpstreamAddr:   s.Session.GetUpstreamAddr(),
			StartedAt:      s.Session.GetStartedAt(),
			Streamable:     s.Session.GetStreamable(),
		})
	}
	errMsgs := make([]string, 0, len(errs))
	for _, e := range errs {
		errMsgs = append(errMsgs, e.Error())
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sessions": out,
		"errors":   errMsgs,
	})
}

// parseSessionPath splits "/api/v1/sessions/{instance}/{id}[/stream]" into
// its components. The input must be the raw (still percent-encoded) path so
// that instance IDs containing "/" (e.g. "host/[::]:2222") survive the split;
// each returned segment is percent-decoded.
func parseSessionPath(escapedPath string) (instance, id, action string, ok bool) {
	const prefix = "/api/v1/sessions/"
	if !strings.HasPrefix(escapedPath, prefix) {
		return "", "", "", false
	}
	rest := strings.TrimPrefix(escapedPath, prefix)
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] == "" || parts[1] == "" {
		return "", "", "", false
	}
	inst, err := url.PathUnescape(parts[0])
	if err != nil {
		return "", "", "", false
	}
	sid, err := url.PathUnescape(parts[1])
	if err != nil {
		return "", "", "", false
	}
	if len(parts) >= 3 {
		if parts[2] == "" {
			// reject trailing slash like /sessions/inst/id/
			return "", "", "", false
		}
		act, err := url.PathUnescape(parts[2])
		if err != nil {
			return "", "", "", false
		}
		action = act
	}
	return inst, sid, action, true
}

func (h *handler) sessionByID(w http.ResponseWriter, r *http.Request) {
	path := r.URL.EscapedPath()
	instance, id, action, ok := parseSessionPath(path)
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	switch action {
	case "":
		if r.Method == http.MethodDelete {
			h.killSession(w, r, instance, id)
			return
		}
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	case "stream":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		h.streamSession(w, r, instance, id)
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

func (h *handler) killSession(w http.ResponseWriter, r *http.Request, instance, id string) {
	if !h.opts.AllowKill {
		writeError(w, http.StatusForbidden, "kill is disabled on this server (--allow-kill=false)")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	killed, err := h.agg.KillSession(ctx, instance, id)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"killed": killed})
}

// streamSession opens an SSE response and forwards admin frames as they
// arrive. Each event is named after the frame kind ("header", "o", "i",
// "r") and carries a JSON payload.
func (h *handler) streamSession(w http.ResponseWriter, r *http.Request, instance, id string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	send := func(event string, payload any) error {
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	}

	err := h.agg.StreamSession(r.Context(), instance, id, true, func(frame *libadmin.SessionFrame) error {
		if hdr := frame.GetHeader(); hdr != nil {
			return send("header", map[string]any{
				"width":      hdr.GetWidth(),
				"height":     hdr.GetHeight(),
				"timestamp":  hdr.GetTimestamp(),
				"env":        hdr.GetEnv(),
				"channel_id": hdr.GetChannelId(),
			})
		}
		if ev := frame.GetEvent(); ev != nil {
			return send(ev.GetKind(), map[string]any{
				"data":       base64.StdEncoding.EncodeToString(ev.GetData()),
				"channel_id": ev.GetChannelId(),
			})
		}
		return nil
	})
	if err != nil && r.Context().Err() == nil {
		log.Debugf("stream %s/%s ended: %v", instance, id, err)
		_ = send("error", map[string]string{"error": err.Error()})
	}
}
