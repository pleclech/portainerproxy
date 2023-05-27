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

package portainer

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

var containersActionsThatNeedUpgrade = map[string]struct{}{
	"attach": {},
	"exec":   {},
	"start":  {},
	"wait":   {},
}

type PortainerEnv struct {
	url         url.URL
	serviceName string
	username    string
	apikey      string
	envID       string
}

func (p PortainerEnv) GetDockerEndpointURL(path string) *url.URL {
	u, _ := url.Parse(p.url.String() + "/api/endpoints/" + p.envID + "/docker/" + strings.TrimPrefix(path, "/"))
	return u
}

func (p PortainerEnv) SetHeaders(r *http.Request) {
	if p.apikey != "" {
		r.Header.Set("x-api-key", p.apikey)
	}
}

func (p PortainerEnv) NewRequest(path string, r *http.Request) *http.Request {
	r2 := &http.Request{}
	*r2 = *r

	if IsUpgradeRequest(r) && r.Header.Get("Upgrade") == "tcp" {
		u, _ := url.Parse("http://docker/" + strings.TrimPrefix(path, "/"))
		r2.URL = u
	} else {
		r2.URL = p.GetDockerEndpointURL(path)
		p.SetHeaders(r2)
	}

	if p.serviceName != "" {
		r2.Host = p.serviceName
	} else {
		r2.Host = r2.URL.Host
	}

	r2.RequestURI = r2.URL.RequestURI()

	return r2
}

type PortainerInfo struct {
	ResourceControl *struct {
		ID         int    `json:"Id"`
		ResourceID string `json:"ResourceId"`
	} `json:"ResourceControl"`
}

type PartialContainerInfo struct {
	ID        string         `json:"Id"`
	Portainer *PortainerInfo `json:"Portainer"`
}

func (p PortainerEnv) IsAllowed(r *http.Request) bool {
	paths := strings.Split(r.URL.Path, "/")

	lPaths := len(paths)

	if lPaths < 3 {
		return true
	}

	if _, ok := containersActionsThatNeedUpgrade[paths[lPaths-1]]; !ok {
		return true
	}

	if paths[lPaths-3] != "containers" {
		return true
	}

	containerID := paths[lPaths-2]

	// check if user is allowed to access this container
	// from portainer api
	// create request
	req, err := http.NewRequest("GET", p.url.String()+"/api/endpoints/"+p.envID+"/docker/containers/"+containerID+"/json", nil)
	if err != nil {
		log.Debugf(err.Error())
		return false
	}

	p.SetHeaders(req)

	// read response json
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Debugf(err.Error())
		return false
	}
	defer resp.Body.Close()

	// read body and unmarshal into PartialContainerInfo
	var containerInfo PartialContainerInfo
	err = json.NewDecoder(resp.Body).Decode(&containerInfo)
	if err != nil {
		log.Debugf(err.Error())
		return false
	}

	if containerInfo.Portainer == nil || containerInfo.Portainer.ResourceControl == nil {
		return false
	}

	return containerInfo.Portainer.ResourceControl.ResourceID != ""
}

var ErrInvalidPortainerURL error

func (p *Proxy) NewPortainerEnv(query string, serviceName string) (*PortainerEnv, error) {
	// trim space and '/'
	query = strings.Trim(query, " /")

	// parse query
	queryMap, err := url.ParseQuery(query)
	if err != nil {
		return nil, err
	}

	portainerURL := p.portainerURL

	// get url from queryMap
	tmp := queryMap.Get("url")
	if tmp == "" {
		if portainerURL == nil {
			return nil, fmt.Errorf("url parameter is required in in docker host")
		}
	} else {
		// bug when receiving url , miss one / into the protocol
		if !strings.HasPrefix(tmp, "http://") && !strings.HasPrefix(tmp, "https://") {
			if strings.HasPrefix(tmp, "http:/") {
				tmp = strings.Replace(tmp, "http:/", "http://", 1)
			} else if strings.HasPrefix(tmp, "https:/") {
				tmp = strings.Replace(tmp, "https:/", "https://", 1)
			} else {
				return nil, fmt.Errorf("tmp %v is not valid, must start with http:// or https://", tmp)
			}
		}

		tmp = strings.TrimSuffix(tmp, "/")
		tmpURL, err := url.Parse(tmp)
		if err != nil {
			return nil, err
		}
		portainerURL = tmpURL
	}

	// get user from queryMap
	user := queryMap.Get("user")
	if user == "" && portainerURL.User != nil {
		user = portainerURL.User.Username()
	}

	if user == "" {
		return nil, ErrInvalidPortainerURL
	}

	// get apikey from queryMap
	apikey := queryMap.Get("apikey")
	if apikey == "" && portainerURL.User != nil {
		apikey, _ = portainerURL.User.Password()
	}
	if apikey == "" {
		return nil, ErrInvalidPortainerURL
	}

	// get envid from queryMap
	envid := queryMap.Get("envid")
	if envid == "" {
		return nil, fmt.Errorf("envid parameter is required in in docker host")
	}

	url := &url.URL{}
	*url = *portainerURL
	url.User = nil

	return &PortainerEnv{
		url:         *url,
		serviceName: serviceName,
		username:    user,
		apikey:      apikey,
		envID:       envid,
	}, nil
}

type Proxy struct {
	portainerURL         *url.URL
	portainerServiceName string
	dialDocker           func() (net.Conn, error)
	listenAddr           string
}

type ConnCloser interface {
	CloseRead() error
	CloseWrite() error
}

func proxyData(sourceConn, destConn net.Conn) error {
	sourceCloser, ok := sourceConn.(ConnCloser)
	if !ok {
		return fmt.Errorf("source connection is not connection closer")
	}
	destCloser, ok := destConn.(ConnCloser)
	if !ok {
		return fmt.Errorf("destination connection is not connection closer")
	}

	wg := &sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, err := io.Copy(sourceConn, destConn)
		if err != nil {
			log.Errorf("Error copying data from destination to source: %v", err)
		}
		sourceCloser.CloseWrite()
		destCloser.CloseRead()
	}()

	go func() {
		defer wg.Done()
		_, err := io.Copy(destConn, sourceConn)
		if err != nil {
			log.Errorf("Error copying data from source to destination: %v", err)
		}
		sourceCloser.CloseRead()
		destCloser.CloseWrite()
	}()

	wg.Wait()
	return nil
}

func GetAddress(url url.URL) string {
	if strings.Contains(url.Host, ":") {
		return url.Host
	}
	if url.Scheme == "http" {
		return url.Host + ":80"
	}
	if url.Scheme == "https" {
		return url.Host + ":443"
	}
	return url.Host
}

func IsUpgradeRequest(req *http.Request) bool {
	con := req.Header.Get("Connection")
	return strings.Contains(strings.ToLower(con), "upgrade")
}

// func (p *Proxy) tryUpgrade(dialer func(network string, address string) (net.Conn, error), w http.ResponseWriter, req *http.Request) (bool, error) {
func (p *Proxy) tryUpgrade(w http.ResponseWriter, r *http.Request) (bool, error) {
	if !IsUpgradeRequest(r) {
		return false, nil
	}

	var (
		err         error
		backendConn net.Conn
	)

	if r.Header.Get("Upgrade") == "tcp" {
		// fallback to tcp using socket path
		log.Debugf("Upgrading connection to TCP")
		backendConn, err = p.dialDocker()
	} else {
		// fallback to tcp using host and port
		log.Debugf("Upgrading connection to TCP using host: %s", GetAddress(*r.URL))
		backendConn, err = net.Dial("tcp", GetAddress(*r.URL))
	}

	if err != nil {
		return true, err
	}

	clientConn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return true, err
	}

	if err = r.Write(backendConn); err != nil {
		return true, fmt.Errorf("error writing request to backend: %v", err)
	}

	err = proxyData(backendConn, clientConn)

	return true, err
}

func ExtractQueryAndPath(requestURI string) (query string, path string) {
	path = "/"
	query = ""

	// query start with '/--'
	idx := strings.Index(requestURI, "/--")

	if idx >= 0 {
		query = requestURI[idx+3:]

		// cut query after '--/'
		idx = strings.Index(requestURI, "--/")
		if idx > -1 {
			path = query[idx-1:]
			query = query[:idx-3]
		}
	}

	return
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	query, path := ExtractQueryAndPath(r.RequestURI)

	action := filepath.Base(r.URL.Path)

	if _, ok := containersActionsThatNeedUpgrade[action]; ok {
		r.Header.Set("Connection", "Upgrade")
		r.Header.Set("Upgrade", "tcp")
	}

	pEnv, err := p.NewPortainerEnv(query, p.portainerServiceName)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	r = pEnv.NewRequest(path, r)

	if !pEnv.IsAllowed(r) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorized"))
		return
	}

	// Create the reverse proxy with the target URL
	proxy := httputil.NewSingleHostReverseProxy(&pEnv.url)

	// Set up a custom transport for handling HTTPS requests
	proxy.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
	}

	upgrade, err := p.tryUpgrade(w, r)
	if err != nil {
		log.Errorf("Error while trying to upgrade connection: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	} else if upgrade {
		return
	}

	proxy.ServeHTTP(w, r)
}

func NewProxy(portainerURL, dockerHost string, listenAddr string, portainerServiceName string) (*Proxy, error) {
	host, err := url.Parse(dockerHost)
	if err != nil {
		return nil, fmt.Errorf("invalid docker host : %w", err)
	}

	var dial func() (net.Conn, error)

	switch host.Scheme {
	case "unix":
		dial = func() (net.Conn, error) {
			return net.Dial("unix", host.Path)
		}
	case "tcp":
		address := GetAddress(*host)
		dial = func() (net.Conn, error) {
			return net.Dial("tcp", address)
		}
	default:
		return nil, fmt.Errorf("invalid docker host scheme : %s expecting tcp or unix", host.Scheme)
	}

	var url *url.URL
	if portainerURL != "" {
		if !strings.HasPrefix(portainerURL, "https") && !strings.HasPrefix(portainerURL, "http") {
			portainerURL = "http://" + portainerURL
		}
		url, err = url.Parse(portainerURL)
		if err != nil {
			return nil, fmt.Errorf("invalid portainer url : %w", err)
		}
	}

	listenAddr = "tcp://" + listenAddr

	errorMsg := fmt.Sprintf("set your docker host like:\n\t%s/--url=http(s)://user:apikey@host:port&envid=??--/\n", listenAddr)
	if portainerURL != "" {
		errorMsg = fmt.Sprintf("%sor to use the default portainer url:\n\t%s/--user=???&apikey=???&envid=??--/", errorMsg, listenAddr)
	}

	ErrInvalidPortainerURL = fmt.Errorf(errorMsg)

	return &Proxy{
		portainerURL:         url,
		portainerServiceName: portainerServiceName,
		dialDocker:           dial,
		listenAddr:           listenAddr,
	}, nil
}
