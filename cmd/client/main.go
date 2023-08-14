package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/Azure/aks-tls-bootstrap-client/pkg/client"
	"github.com/sirupsen/logrus"
)

func main() {
	var (
		logger = logrus.New()

		clientID = flag.String(
			"client-id",
			"",
			"The client ID for the assigned identity to use.",
		)
		logFormat = flag.String(
			"log-format",
			"json",
			"Log format: json or text, default: json",
		)
		nextProto = flag.String(
			"next-proto",
			"aks-tls-bootstrap",
			"ALPN Next Protocol value to send.",
		)
		debug = flag.Bool(
			"debug",
			false,
			"enable debug logging (WILL LOG AUTHENTICATION DATA)",
		)
	)

	flag.Parse()
	logger.SetReportCaller(true)

	switch strings.ToLower(*logFormat) {
	case "text":
		logger.SetFormatter(&logrus.TextFormatter{})
	default:
		logger.SetFormatter(&logrus.JSONFormatter{})
	}

	if *debug {
		logger.SetLevel(logrus.DebugLevel)
	}

	bootstrapClient := client.NewTLSBootstrapClient(logger, *clientID, *nextProto)

	token, err := bootstrapClient.GetBootstrapToken()
	if err != nil {
		logger.Fatalf("Failed to retrieve bootstrap token: %s", err)
	}

	//nolint:forbidigo // kubelet needs the token printed to stdout
	fmt.Println(token)
}
