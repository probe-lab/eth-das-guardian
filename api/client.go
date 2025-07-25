package api

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type ClientConfig struct {
	Endpoint       string
	StateTimeout   time.Duration
	QueryTimeout   time.Duration
	CustomClClient string
	Logger         *log.Logger
}

type Client struct {
	cfg            ClientConfig
	base           *url.URL
	client         *http.Client
	customClClient string
}

func NewClient(cfg ClientConfig) (*Client, error) {
	// http client for the communication
	httpCli := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   cfg.QueryTimeout,
				KeepAlive: 40 * time.Second,
			}).DialContext,
			IdleConnTimeout: 600 * time.Second,
		},
	}

	urlBase, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return nil, errors.Wrap(err, "composing API's base URL")
	}

	cli := &Client{
		cfg:            cfg,
		base:           urlBase,
		client:         httpCli,
		customClClient: cfg.CustomClClient,
	}

	return cli, nil
}

func (c *Client) CheckConnection(ctx context.Context) error {
	version, err := c.GetNodeVersion(ctx)
	if err != nil {
		return errors.Wrap(err, "testing connectivity")
	}

	c.cfg.Logger.WithFields(log.Fields{
		"node-version": version.Data.Version,
	}).Info("successfull connection to the beacon-api")

	return nil
}

func (c *Client) get(
	ctx context.Context,
	timeout time.Duration,
	endpoint string,
	query string,
) ([]byte, error) {
	var respBody []byte

	// set deadline
	opCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	callURL := composeCallURL(c.base, endpoint, query)
	req, err := http.NewRequestWithContext(opCtx, http.MethodGet, callURL.String(), nil)
	if err != nil {
		return []byte{}, errors.Wrap(err, "unable to compose call URL")
	}

	// we will only handle JSONs
	req.Header.Set("Accept", "application/json")
	// select an specific cl client from the work-balancer if defined
	if c.customClClient != "" {
		req.Header.Set("X-Dugtrio-Next-Endpoint", c.customClClient)
	}

	l := c.cfg.Logger.WithFields(log.Fields{
		"url":    callURL,
		"method": req.Method,
	})
	l.Info("requesting beacon API")
	resp, err := c.client.Do(req)
	if err != nil {
		l.WithError(err).Warn("error requesting beacon API")
		return respBody, errors.Wrap(err, fmt.Sprintf("unable to request URL %s", callURL.String()))
	}
	if resp == nil {
		err := errors.New("got empty response from the API")
		l.WithError(err).Warn("error requesting beacon API")
		return respBody, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		l.WithFields(log.Fields{
			"status_code": resp.StatusCode,
			"status":      resp.Status,
		}).Warn("beacon API returned non-success status code")

		// Read the error response body for better error messages
		errorBody, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return respBody, fmt.Errorf("unable to read api-response %s", err.Error())
		}
		return respBody, fmt.Errorf("beacon API request failed %s - %s", resp.Status, string(errorBody))
	}

	respBody, err = io.ReadAll(resp.Body)
	if err != nil {
		l.WithError(err).Warn("failed to read response body")
		return respBody, errors.Wrap(err, "reading response body")
	}

	if len(respBody) > 1024 {
		l.Infof("successful beacon API response: [omitted due to length %d]", len(respBody))
	} else {
		l.Infof("successful beacon API response: %s", respBody)
	}

	return respBody, nil
}

func composeCallURL(base *url.URL, endpoint, query string) *url.URL {
	callURL := *base
	callURL.Path += endpoint
	if callURL.RawQuery == "" {
		callURL.RawQuery = query
	} else if query != "" {
		callURL.RawQuery = fmt.Sprintf("%s&%s", callURL.RawQuery, query)
	}

	return &callURL
}

func (c *Client) Close() error {
	c.client.CloseIdleConnections()
	return nil
}
