package client

import (
	"strings"

	"github.com/sirupsen/logrus"
)

func GetLogger(format string, debug bool) *logrus.Logger {
	logger := logrus.New()
	logger.SetReportCaller(true)

	switch strings.ToLower(format) {
	case "text":
		logger.SetFormatter(&logrus.TextFormatter{})
	default:
		logger.SetFormatter(&logrus.JSONFormatter{})
	}

	if debug {
		logger.SetLevel(logrus.DebugLevel)
	}

	return logger
}
