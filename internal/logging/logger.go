package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/chrismfz/nxs/internal/config"
)

type Logger struct {
	sl       *slog.Logger
	hostname string
}

func New(cfg *config.Config) (*Logger, error) {
	if err := os.MkdirAll(cfg.Main.LogDir, 0755); err != nil {
		return nil, err
	}

	logPath := filepath.Join(cfg.Main.LogDir, "nxs.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, err
	}

	hostname := cfg.Main.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}

	// JSON to file; warnings and above also go to stderr
	fileHandler := slog.NewJSONHandler(f, &slog.HandlerOptions{Level: slog.LevelDebug})
	stderrHandler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})

	sl := slog.New(&multiHandler{handlers: []slog.Handler{fileHandler, stderrHandler}}).
		With("hostname", hostname)

	return &Logger{sl: sl, hostname: hostname}, nil
}

func NewNop() *Logger {
	return &Logger{sl: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func (l *Logger) Debug(msg string, args ...any) { l.sl.Debug(msg, args...) }
func (l *Logger) Info(msg string, args ...any)  { l.sl.Info(msg, args...) }
func (l *Logger) Warn(msg string, args ...any)  { l.sl.Warn(msg, args...) }
func (l *Logger) Error(msg string, args ...any) { l.sl.Error(msg, args...) }

func (l *Logger) With(args ...any) *Logger {
	return &Logger{sl: l.sl.With(args...), hostname: l.hostname}
}

// multiHandler fans out to multiple slog handlers.
type multiHandler struct {
	handlers []slog.Handler
}

func (m *multiHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return true
}

func (m *multiHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range m.handlers {
		if h.Enabled(ctx, r.Level) {
			_ = h.Handle(ctx, r)
		}
	}
	return nil
}

func (m *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	hs := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		hs[i] = h.WithAttrs(attrs)
	}
	return &multiHandler{handlers: hs}
}

func (m *multiHandler) WithGroup(name string) slog.Handler {
	hs := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		hs[i] = h.WithGroup(name)
	}
	return &multiHandler{handlers: hs}
}
