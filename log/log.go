package log

import (
	"fmt"
	"os"
)

// Messages with a log level <= this value shall be logged
// -1 means no logging
var logLevelPolicy = -1

// Log levels, partly mapped on syslog log levels
const (
	LogLevelErr   = 3 // error conditions
	LogLevelWarn  = 4 // warning conditions
	LogLevelInfo  = 6 // informational message
	LogLevelDebug = 7 //
)

func SetLogLevel(level int) {
	logLevelPolicy = level
}

func Log(level int, format string, v ...any) {
	if level <= logLevelPolicy {
		fmt.Fprintf(os.Stderr, format, v...)
		fmt.Fprintf(os.Stderr, "\n")
	}
}

func Debug(format string, v ...any) {
	Log(LogLevelDebug, format, v...)
}

func Info(format string, v ...any) {
	Log(LogLevelInfo, format, v...)
}

func Warning(format string, v ...any) {
	Log(LogLevelWarn, format, v...)
}

func Error(format string, v ...any) {
	Log(LogLevelErr, format, v...)
}
