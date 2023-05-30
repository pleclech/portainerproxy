// MIT License
//
// Copyright (c) 2023 pleclech
// Github: https://github.com/pleclech
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pleclech/portainerproxy/pkg/portainer"
	"go.uber.org/zap"
)

const (
	defaultDockerHost = "unix:///var/run/docker.sock"
	defaultAddress    = ":8080"
)

var (
	version = "0.0.0"
)

func main() {
	// Parse command-line flags
	versionFlag := flag.Bool("version", false, "Print the version")
	portainerURL := flag.String("portainer", "", "Portainer URL")
	portainerServiceName := flag.String("portainer-service-name", "", "if running docker, the name of the portainer service")
	dockerHost := flag.String("host", defaultDockerHost, "real docker host")
	useHTTPS := flag.Bool("https", false, "Enable HTTPS")
	certFile := flag.String("cert", "", "Path to the certificate file")
	keyFile := flag.String("key", "", "Path to the key file")
	address := flag.String("address", defaultAddress, "Address and port to listen on")
	debugFlag := flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()

	// Print the version if the version flag is provided
	if *versionFlag {
		fmt.Printf("v%s", version)
		return
	}

	var logger *zap.Logger

	// Enable debug mode if the debug flag is provided
	if *debugFlag {
		// set debug mode for zap
		logger, _ = zap.NewDevelopment()
		// log.SetLevel(log.DebugLevel)
	} else {
		logger, _ = zap.NewProduction()
	}

	defer logger.Sync()

	// split address into host and port
	host, port, err := net.SplitHostPort(*address)
	if err != nil {
		logger.Fatal("Invalid address", zap.Error(err))
		// log.Fatal(err)
	}

	// if host is empty, set it to localhost
	if host == "" {
		host = "localhost"
	}

	*address = host + ":" + port

	proxy, err := portainer.NewProxy(logger, *portainerURL, *dockerHost, *address, *portainerServiceName)
	if err != nil {
		logger.Fatal(err.Error())
	}

	// Create an HTTP server
	server := &http.Server{
		Addr:    *address,
		Handler: proxy,
	}

	// Start the HTTP/HTTPS server based on the flag
	go func() {
		logger.Info("Starting proxy server...",
			zap.String("version", version),
			zap.String("Portainer url", *portainerURL),
			zap.String("Docker host", *dockerHost),
			zap.Bool("debug", *debugFlag))

		logger.Sync()

		var err error
		if *useHTTPS {
			if *certFile == "" || *keyFile == "" {
				logger.Fatal("Both certificate file and key file paths must be provided for HTTPS mode")
			}

			logger.Info("HTTPS proxy server listening on", zap.String("address", *address))
			err = server.ListenAndServeTLS(*certFile, *keyFile)
		} else {
			logger.Info("HTTP proxy server listening on", zap.String("address", *address))
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			logger.Fatal(err.Error())
		}
	}()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Block until a shutdown signal is received
	<-shutdown

	// Create a context with a timeout for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt to gracefully shut down the server
	if err := server.Shutdown(ctx); err != nil {
		logger.Fatal("Server shutdown error", zap.Error(err))
	}

	// and then shutdown the server
	logger.Info("Shutting down the server...")
}
