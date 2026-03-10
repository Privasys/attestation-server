package main

import (
	"encoding/json"
	"os"
	"time"
)

// Structured JSON logger — zero external dependencies.

func logEvent(level string, msg string, kvs ...interface{}) {
	entry := map[string]interface{}{
		"ts":    time.Now().UTC().Format(time.RFC3339),
		"level": level,
		"msg":   msg,
	}
	for i := 0; i+1 < len(kvs); i += 2 {
		key, _ := kvs[i].(string)
		if key != "" {
			entry[key] = kvs[i+1]
		}
	}
	json.NewEncoder(os.Stderr).Encode(entry)
}

func logInfo(msg string, kvs ...interface{})  { logEvent("info", msg, kvs...) }
func logWarn(msg string, kvs ...interface{})  { logEvent("warn", msg, kvs...) }
func logError(msg string, kvs ...interface{}) { logEvent("error", msg, kvs...) }

func logFatal(msg string, kvs ...interface{}) {
	logEvent("fatal", msg, kvs...)
	os.Exit(1)
}
