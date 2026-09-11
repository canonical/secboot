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

func Logf(level int, format string, v ...any) {
	if level <= logLevelPolicy {
		fmt.Fprintf(os.Stderr, format, v...)
		fmt.Fprintf(os.Stderr, "\n")
	}
}

func Debugf(format string, v ...any) {
	Logf(LogLevelDebug, format, v...)
}

func Infof(format string, v ...any) {
	Logf(LogLevelInfo, format, v...)
}

func Warningf(format string, v ...any) {
	Logf(LogLevelWarn, format, v...)
}

func Errorf(format string, v ...any) {
	Logf(LogLevelErr, format, v...)
}
