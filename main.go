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
	log "github.com/sirupsen/logrus"
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

	// Enable debug mode if the debug flag is provided
	if *debugFlag {
		log.SetLevel(log.DebugLevel)
	}

	// split address into host and port
	host, port, err := net.SplitHostPort(*address)
	if err != nil {
		log.Fatal(err)
	}

	// if host is empty, set it to localhost
	if host == "" {
		host = "localhost"
	}

	*address = host + ":" + port

	proxy, err := portainer.NewProxy(*portainerURL, *dockerHost, *address, *portainerServiceName)
	if err != nil {
		log.Fatal(err)
	}

	// Create an HTTP server
	server := &http.Server{
		Addr:    *address,
		Handler: proxy,
	}

	// Start the HTTP/HTTPS server based on the flag
	go func() {
		log.Infof("Starting proxy server...")
		log.Infof("Version: %s", version)
		log.Infof("Portainer URL: %s", *portainerURL)
		log.Infof("Docker host: %s", *dockerHost)
		log.Infof("Debug mode: %v", *debugFlag)

		var err error
		if *useHTTPS {
			if *certFile == "" || *keyFile == "" {
				log.Fatal("Both certificate file and key file paths must be provided for HTTPS mode")
			}

			log.Infof("HTTPS proxy server listening on %v\n", *address)
			err = server.ListenAndServeTLS(*certFile, *keyFile)
		} else {
			log.Infof("HTTP proxy server listening on %v", *address)
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
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
		log.Fatalf("Server shutdown error: %s", err)
	}

	// and then shutdown the server
	log.Infof("Shutting down the server...")
}
