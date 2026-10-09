package log

import (
	"fmt"
	"io"
	"os"
)

// Messages with a log level <= this value shall be logged
// -1 means no logging
var logLevelPolicy = -1

// Default underlying destination of log messages
var output io.Writer = os.Stderr

// Log levels, partly mapped on syslog log levels
const (
	LogLevelErr   = 3 // error conditions
	LogLevelWarn  = 4 // warning conditions
	LogLevelInfo  = 6 // informational message
	LogLevelDebug = 7 //
)

// SetLogLevel sets the log level policy: only messages of this level
// and those with a more significant level shall be logged.
func SetLogLevel(level int) {
	logLevelPolicy = level
}

// SetOutput modifies the underlying destination of log messages
func SetOutput(newOutput io.Writer) {
	output = newOutput
}

func Logf(level int, format string, v ...any) {
	if level <= logLevelPolicy {
		s := fmt.Sprintf(format, v...)
		fmt.Fprintln(output, s)
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
