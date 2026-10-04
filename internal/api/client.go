package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ErrConflict reports that a migration lost to a newer epoch. The error
// is a *ConflictError carrying the session as it is now.
var ErrConflict = errors.New("api: session has moved to a newer epoch")

// ConflictError is returned by Migrate on a conflict.
type ConflictError struct{ Current Session }

func (e *ConflictError) Error() string {
	return fmt.Sprintf("%v (now epoch %d: access %s, egress %s)", ErrConflict, e.Current.Epoch, e.Current.Access, e.Current.Egress)
}
func (e *ConflictError) Unwrap() error { return ErrConflict }

// StatusError is any other non-2xx response.
type StatusError struct {
	Code    int
	Message string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("api: controller answered %d: %s", e.Code, e.Message)
}

// Client talks to the controller's HTTP API.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// NewClient returns a client for the controller at baseURL (for example
// "http://10.0.0.1:8080"), authenticating with token.
func NewClient(baseURL, token string) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("api: controller URL %q must be http(s)://host[:port]", baseURL)
	}
	return &Client{base: strings.TrimRight(baseURL, "/"), token: token, http: &http.Client{}}, nil
}

// Host returns the controller's host name or address.
func (c *Client) Host() string {
	u, _ := url.Parse(c.base)
	return u.Hostname()
}

func (c *Client) do(ctx context.Context, method, path, bearer string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e Error
		_ = json.Unmarshal(data, &e)
		if resp.StatusCode == http.StatusConflict && e.Session != nil {
			return &ConflictError{Current: *e.Session}
		}
		msg := e.Error
		if msg == "" {
			msg = strings.TrimSpace(string(data))
		}
		return &StatusError{Code: resp.StatusCode, Message: msg}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

func waitQuery(after uint64, wait time.Duration) string {
	return "?after=" + strconv.FormatUint(after, 10) + "&wait=" + strconv.FormatInt(wait.Milliseconds(), 10)
}

// RegisterGateway registers (or re-registers) gateway id.
func (c *Client) RegisterGateway(ctx context.Context, id string, req RegisterGatewayRequest) (RegisterGatewayResponse, error) {
	var out RegisterGatewayResponse
	err := c.do(ctx, http.MethodPut, "/v1/gateways/"+url.PathEscape(id), c.token, req, &out)
	return out, err
}

// ReportLinks sends gateway id's backbone measurements; it is also the
// gateway's heartbeat.
func (c *Client) ReportLinks(ctx context.Context, id string, rep LinkReport) error {
	return c.do(ctx, http.MethodPost, "/v1/gateways/"+url.PathEscape(id)+"/links", c.token, rep, nil)
}

// GatewayState returns the state once its version is above after, or
// after wait has passed, whichever is first.
func (c *Client) GatewayState(ctx context.Context, after uint64, wait time.Duration) (GatewayState, error) {
	var out GatewayState
	err := c.do(ctx, http.MethodGet, "/v1/gateway-state"+waitQuery(after, wait), c.token, nil, &out)
	return out, err
}

// Gateways lists the registered gateways, authenticated with the client
// token.
func (c *Client) Gateways(ctx context.Context) ([]Gateway, error) {
	var out []Gateway
	err := c.do(ctx, http.MethodGet, "/v1/gateways", c.token, nil, &out)
	return out, err
}

// CreateSession opens (or reopens) a session.
func (c *Client) CreateSession(ctx context.Context, req CreateSessionRequest) (CreateSessionResponse, error) {
	var out CreateSessionResponse
	err := c.do(ctx, http.MethodPost, "/v1/sessions", c.token, req, &out)
	return out, err
}

// ClientState returns session id's state, long-polling like GatewayState.
func (c *Client) ClientState(ctx context.Context, id, secret string, after uint64, wait time.Duration) (ClientState, error) {
	var out ClientState
	err := c.do(ctx, http.MethodGet, "/v1/sessions/"+url.PathEscape(id)+"/state"+waitQuery(after, wait), secret, nil, &out)
	return out, err
}

// Migrate moves session id; see MigrateRequest.
func (c *Client) Migrate(ctx context.Context, id, secret string, req MigrateRequest) (Session, error) {
	var out Session
	err := c.do(ctx, http.MethodPost, "/v1/sessions/"+url.PathEscape(id)+"/migrate", secret, req, &out)
	return out, err
}
