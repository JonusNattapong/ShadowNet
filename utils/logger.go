package utils

import (
	"os"

	"github.com/sirupsen/logrus"
)

// Log is the global logger instance
var Log *logrus.Logger

// InitLogger initializes the global logger with standard configuration
func InitLogger() {
    Log = logrus.New()
    Log.SetOutput(os.Stdout)
    Log.SetFormatter(&logrus.TextFormatter{
        FullTimestamp:   true,
        TimestampFormat: "2006-01-02 15:04:05",
    })

    // Set log level based on environment
    if os.Getenv("DEBUG") == "true" {
        Log.SetLevel(logrus.DebugLevel)
    } else {
        Log.SetLevel(logrus.InfoLevel)
    }

    // Add file and line number to log entries
    Log.SetReportCaller(true)
}

// InitTestLogger initializes a logger for testing
func InitTestLogger() {
    Log = logrus.New()
    Log.SetOutput(os.Stdout)
    Log.SetFormatter(&logrus.TextFormatter{
        DisableTimestamp: true,
    })
    Log.SetLevel(logrus.FatalLevel) // Only show fatal errors during tests
}
