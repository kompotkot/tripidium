package logger

import (
	"log/slog"
	"os"

	"github.com/kompotkot/tripidium/internal/types"
)

// Initialize main logger
func New(lc types.LoggerConfig) *slog.Logger {
	var logHandler slog.Handler

	// Parse the log level
	var logLevel slog.Level
	switch lc.Level {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	logOpts := &slog.HandlerOptions{
		Level: logLevel,
	}

	// Parse the log format
	if lc.Format == "json" {
		logHandler = slog.NewJSONHandler(os.Stdout, logOpts)
	} else {
		logHandler = slog.NewTextHandler(os.Stdout, logOpts)
	}

	return slog.New(logHandler)
}
