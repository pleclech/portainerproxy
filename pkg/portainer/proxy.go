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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

type actionConfig struct {
	tag       string
	proxyMode proxyMode
	check     bool
}

func (a actionConfig) getContainerID(paths []string) string {
	if a.tag == "containers" {
		lPaths := len(paths)
		if lPaths < 3 {
			return ""
		}
		if paths[lPaths-3] != "containers" {
			return ""
		}
		return paths[lPaths-2]
	}
	return ""
}

var actionConfigUpgrade = &actionConfig{
	tag:       "",
	proxyMode: proxyModeDockerUpgrade,
	check:     false,
}

var actionConfigContainersUpgrade = &actionConfig{
	tag:       "containers",
	proxyMode: proxyModeDockerUpgrade,
	check:     true,
}

var actionConfigImageDirect = &actionConfig{
	tag:       "images",
	proxyMode: proxyModeDockerDirect,
	check:     false,
}

var actionConfigProxy = &actionConfig{
	proxyMode: proxyModeProxy,
	check:     false,
}

var actionsConfig = map[string]*actionConfig{
	"containers/exec":  actionConfigContainersUpgrade,
	"containers/start": actionConfigContainersUpgrade,
	"containers/wait":  actionConfigContainersUpgrade,
	"images/create":    actionConfigUpgrade,
	"grpc":             actionConfigUpgrade,
	"session":          actionConfigUpgrade,
}

func getActionConfig(paths []string, isUpgradable bool) (string, *actionConfig) {
	var key string

	lPaths := len(paths)

	if lPaths > 0 {
		key = paths[lPaths-1]
		if lPaths >= 2 {
			if paths[lPaths-2] == "images" {
				key = "images/" + key
			} else {
				if lPaths >= 3 && paths[lPaths-3] == "containers" {
					key = "containers/" + key
				}
			}
		}
	}

	if cfg, ok := actionsConfig[key]; ok {
		return key, cfg
	}

	if isUpgradable {
		return key, actionConfigUpgrade
	}

	return key, actionConfigProxy
}

// censor all but the  first and last characters
func Censor(str string, keepFirst int, keepLast int) string {
	if str == "" {
		return ""
	}
	tLen := keepFirst + keepLast
	lStr := len(str)
	if lStr < tLen {
		return str[:1] + "****" + str[lStr-1:]
	}
	return str[:keepFirst] + "****" + str[lStr-keepLast:]
}

type PortainerEnv struct {
	logger      *zap.Logger
	connID      int64
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
	// show x-api-key in debug logs
	// but censored all but the 4 first and 1 last characters
	if p.logger.Level() == zap.DebugLevel {
		p.logger.Debug(fmt.Sprintf("connection#%d", p.connID), zap.String("x-api-key", Censor(p.apikey, 6, 3)))
	}
}

func newUpgradeRequest(path string, req *http.Request) *http.Request {
	newReq := &http.Request{}
	*newReq = *req
	u, _ := url.Parse("http://docker/" + strings.TrimPrefix(path, "/"))
	newReq.URL = u
	newReq.Host = u.Host
	newReq.RequestURI = u.RequestURI()
	return newReq
}

func (p PortainerEnv) NewRequest(cfg actionConfig, path string, req *http.Request) *http.Request {
	newReq := &http.Request{}
	*newReq = *req

	switch cfg.proxyMode {
	case proxyModeDockerDirect:
		newReq.URL = &url.URL{
			Scheme: "http",
			Host:   "docker",
		}
	case proxyModeDockerUpgrade:
		u, _ := url.Parse("http://docker/" + strings.TrimPrefix(path, "/"))
		newReq.URL = u
	default:
		newReq.URL = p.GetDockerEndpointURL(path)
		p.SetHeaders(newReq)
	}

	if p.serviceName != "" {
		newReq.Host = p.serviceName
	} else {
		newReq.Host = newReq.URL.Host
	}

	newReq.RequestURI = newReq.URL.RequestURI()

	return newReq
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

func (p PortainerEnv) IsAllowed(cfg actionConfig, paths []string, connID int64, w http.ResponseWriter, r *http.Request) bool {
	if !cfg.check {
		return true
	}

	containerID := cfg.getContainerID(paths)
	if containerID == "" {
		return true
	}

	p.logger.Debug(fmt.Sprintf("connection#%d: checking for permission to access container %s", connID, containerID))

	// check if user is allowed to access this container
	// from portainer api
	// create request
	req, err := http.NewRequest("GET", p.url.String()+"/api/endpoints/"+p.envID+"/docker/containers/"+containerID+"/json", nil)
	if err != nil {
		errS := fmt.Errorf("connection#%d: error creating request: %w", connID, err).Error()
		p.logger.Debug(errS)
		http.Error(w, errS, http.StatusInternalServerError)
		return false
	}

	p.SetHeaders(req)

	// read response json
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		errS := fmt.Errorf("connection#%d: error sending request: %w", connID, err).Error()
		p.logger.Debug(errS)
		http.Error(w, errS, http.StatusInternalServerError)
		return false
	}
	defer resp.Body.Close()

	// check status code
	if resp.StatusCode != http.StatusOK {
		if p.logger.Level() == zap.DebugLevel {
			b, _ := httputil.DumpRequest(req, true)
			p.logger.Debug(fmt.Sprintf("connection#%d: received request:\n%s", connID, string(b)))
		}

		// copy resp to w
		w.WriteHeader(resp.StatusCode)
		// copy headers
		for k, v := range resp.Header {
			w.Header()[k] = v
		}

		io.Copy(w, resp.Body)

		return false
	}

	// read body and unmarshal into PartialContainerInfo
	var containerInfo PartialContainerInfo
	err = json.NewDecoder(resp.Body).Decode(&containerInfo)
	if err != nil {
		p.logger.Debug(err.Error())
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return false
	}

	if containerInfo.Portainer == nil || containerInfo.Portainer.ResourceControl == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}

	ok := containerInfo.Portainer.ResourceControl.ResourceID != ""

	p.logger.Debug(fmt.Sprintf("connection#%d: permission to access container %s: %v", connID, containerID, ok))

	return ok
}

var ErrInvalidPortainerURL error

func (p *Proxy) NewPortainerEnv(connID int64, query string, serviceName string) (*PortainerEnv, error) {
	// trim space and '/'
	query = strings.Trim(query, " /")

	p.logger.Debug(fmt.Sprintf("connection#%d: creating new portainer env", connID))

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
		logger:      p.logger,
		connID:      connID,
		url:         *url,
		serviceName: serviceName,
		username:    user,
		apikey:      apikey,
		envID:       envid,
	}, nil
}

type Proxy struct {
	logger               *zap.Logger
	portainerURL         *url.URL
	portainerServiceName string
	dial                 func(ctx context.Context) (net.Conn, error)
	listenAddr           string
	upgradeConnID        int64
}

type ConnReadCloser interface {
	CloseRead() error
}

type ConnWriteCloser interface {
	CloseWrite() error
}

type ConnCloser interface {
	ConnReadCloser
	ConnWriteCloser
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

func (p *Proxy) incConnID() int64 {
	return atomic.AddInt64(&p.upgradeConnID, 1)
}

type LogWriter struct {
	logger *zap.Logger
}

func (l LogWriter) Write(p []byte) (n int, err error) {
	l.logger.Debug(string(p))
	return len(p), nil
}

func (p *Proxy) tryUpgrade(actionCfg actionConfig, w http.ResponseWriter, r *http.Request, connID int64) (bool, error) {
	if actionCfg.proxyMode != proxyModeDockerUpgrade && actionCfg.proxyMode != proxyModeDockerDirect {
		return false, nil
	}

	var (
		err         error
		backendConn net.Conn
	)

	switch r.Header.Get("Upgrade") {
	case "tcp", "h2c":
		p.logger.Debug(fmt.Sprintf("connection#%d: upgrading to TCP", connID))
		backendConn, err = p.dial(r.Context())
	default:
		// fallback to tcp using host and port
		p.logger.Debug(fmt.Sprintf("connection#%d: upgrading to TCP using adress: %s", connID, GetAddress(*r.URL)))
		backendConn, err = net.Dial("tcp", GetAddress(*r.URL))
	}

	if err != nil {
		return true, err
	}

	defer backendConn.Close()

	// When we set up a TCP connection for hijack, there could be long periods
	// of inactivity (a long running command with no output) that in certain
	// network setups may cause ECONNTIMEOUT, leaving the client in an unknown
	// state. Setting TCP KeepAlive on the socket connection will prohibit
	// ECONNTIMEOUT unless the socket connection truly is broken
	if tcpConn, ok := backendConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	// dump request
	if p.logger.Level() == zap.DebugLevel {
		dump, err := httputil.DumpRequest(r, true)
		if err != nil {
			return true, err
		}
		p.logger.Debug(fmt.Sprintf("connection#%d: request: %s", connID, string(dump)))
	}

	if err = r.Write(backendConn); err != nil {
		p.logger.Debug(fmt.Sprintf("connection#%d: error writing request to backend: %v", connID, err))
		return true, nil
	}

	// Upgrade the connection to a TCP connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		return true, fmt.Errorf("connection#%d: hijacking not supported", connID)
	}

	clientConn, bw, err := hj.Hijack()
	if err != nil {
		return true, err
	}

	defer clientConn.Close()

	// dump response
	if p.logger.Level() == zap.DebugLevel {
		teeReader := io.TeeReader(backendConn, clientConn)
		resp, err := http.ReadResponse(bufio.NewReader(teeReader), nil)
		if err != nil {
			return true, err
		}

		b, _ := httputil.DumpResponse(resp, true)
		p.logger.Debug(fmt.Sprintf("connection#%d: response: %s", connID, string(b)))
	}

	var wg sync.WaitGroup
	wg.Add(2)

	var mrClientConn io.Reader
	buffered := bw.Reader.Buffered()

	if buffered > 0 {
		p.logger.Debug(fmt.Sprintf("connection#%d", connID), zap.Int("buffered", buffered))
		lr := io.LimitReader(bw, int64(bw.Reader.Buffered()))
		mrClientConn = io.MultiReader(lr, clientConn)
	} else {
		mrClientConn = clientConn
	}

	cp := func(dst io.Writer, src io.Reader, dir string) {
		defer func() {
			wg.Done()
			if closer, ok := dst.(ConnWriteCloser); ok {
				closer.CloseWrite()
			}
		}()

		_, err := io.Copy(dst, src)
		if err != nil {
			p.logger.Error(fmt.Sprintf("connection#%d: error copying from %s", connID, dir), zap.Error(err))
		}
	}

	go cp(clientConn, backendConn, "backend to client")
	go cp(backendConn, mrClientConn, "client to backend")

	wg.Wait()

	p.logger.Debug(fmt.Sprintf("connection#%d: closed", connID))

	return true, nil
}

func ExtractQueryAndPath(requestURI string) (query string, path string) {
	path = requestURI
	query = ""

	// query start with '/--'
	idx := strings.Index(requestURI, "/--")

	if idx >= 0 {
		query = requestURI[idx+3:]

		// cut query after '--/'
		idx = strings.Index(requestURI, "--/")
		if idx >= 0 {
			path = query[idx-1:]
			query = query[:idx-3]
		}
	}

	return
}

type proxyMode int

const (
	proxyModeProxy proxyMode = iota
	proxyModeDockerDirect
	proxyModeDockerUpgrade
)

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer p.logger.Sync()

	connID := p.incConnID()

	query, qPath := ExtractQueryAndPath(r.RequestURI)

	p.logger.Debug(fmt.Sprintf("connection#%d: relayed to %v", connID, qPath))

	paths := strings.Split(r.URL.Path, "/")

	isUpgrade := IsUpgradeRequest(r)
	action, actionCfg := getActionConfig(paths, isUpgrade)

	if isUpgrade {
		p.logger.Debug(fmt.Sprintf("connection#%d: need upgrade (%s)", connID, action))
	} else {
		if actionCfg.proxyMode == proxyModeDockerUpgrade {
			p.logger.Debug(fmt.Sprintf("connection#%d: force upgrade (%s)", connID, action))
			r.Header.Set("Connection", "Upgrade")
			r.Header.Set("Upgrade", "tcp")
		}
	}

	var proxyURL *url.URL

	if actionCfg.proxyMode != proxyModeDockerUpgrade || actionCfg.check {
		pEnv, err := p.NewPortainerEnv(connID, query, p.portainerServiceName)
		if err != nil {
			p.logger.Debug(fmt.Sprintf("connection#%d: error while getting portainer environment", connID), zap.Error(err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if pEnv == nil {
			p.logger.Debug(fmt.Sprintf("connection#%d: no portainer environment found", connID))
			http.Error(w, "No portainer environment found", http.StatusInternalServerError)
			return
		}

		r = pEnv.NewRequest(*actionCfg, qPath, r)

		if !pEnv.IsAllowed(*actionCfg, paths, connID, w, r) {
			return
		}

		proxyURL = &pEnv.url
	} else {
		r = newUpgradeRequest(qPath, r)
	}

	upgrade, err := p.tryUpgrade(*actionCfg, w, r, connID)
	if err != nil {
		p.logger.Error("Error while trying to upgrade connection", zap.Error(err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if upgrade {
		return
	}

	var proxy *httputil.ReverseProxy

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
	}

	if actionCfg.proxyMode == proxyModeDockerDirect {
		proxyURL = r.URL
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			p.logger.Debug(fmt.Sprintf("connection#%d: dialing docker", connID))
			return p.dial(ctx)
		}
	}

	proxy = httputil.NewSingleHostReverseProxy(proxyURL)
	proxy.Transport = transport

	proxy.ServeHTTP(w, r)
}

func NewProxy(logger *zap.Logger, portainerURL, dockerHost string, listenAddr string, portainerServiceName string) (*Proxy, error) {
	host, err := url.Parse(dockerHost)
	if err != nil {
		return nil, fmt.Errorf("invalid docker host : %w", err)
	}

	var dialNetwork string
	var dialAddr string

	switch host.Scheme {
	case "unix":
		dialNetwork = "unix"
		dialAddr = host.Path
	case "tcp":
		dialNetwork = "tcp"
		dialAddr = GetAddress(*host)
	default:
		return nil, fmt.Errorf("invalid docker host scheme : %s expecting tcp or unix", host.Scheme)
	}

	var url *url.URL
	if portainerURL != "" {
		if !strings.HasPrefix(portainerURL, "https") && !strings.HasPrefix(portainerURL, "http") {
			portainerURL = "https://" + portainerURL
		}
		url, err = url.Parse(portainerURL)
		if err != nil {
			return nil, fmt.Errorf("invalid portainer url : %w", err)
		}
	}

	listenAddr = "tcp://" + listenAddr

	errorMsg := fmt.Sprintf("set your docker host like:\n%s/--url=http(s)://user:apikey@host:port&envid=??--/\n", listenAddr)
	if portainerURL != "" {
		errorMsg = fmt.Sprintf("%sor to use the default portainer url:\n\t%s/--user=???&apikey=???&envid=??--/", errorMsg, listenAddr)
	}

	ErrInvalidPortainerURL = fmt.Errorf(errorMsg)

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	return &Proxy{
		logger:               logger,
		portainerURL:         url,
		portainerServiceName: portainerServiceName,
		dial: func(ctx context.Context) (net.Conn, error) {
			return dialer.DialContext(ctx, dialNetwork, dialAddr)
		},
		listenAddr: listenAddr,
	}, nil
}
