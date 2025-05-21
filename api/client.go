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
	Endpoint     string
	StateTimeout time.Duration
	QueryTimeout time.Duration
}

type Client struct {
	cfg     ClientConfig
	base    *url.URL
	address string
	client  *http.Client
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
		return nil, errors.Wrap(err, "composing Avail API's base URL")
	}

	cli := &Client{
		cfg:    cfg,
		base:   urlBase,
		client: httpCli,
	}

	return cli, nil
}

func (c *Client) CheckConnection(ctx context.Context) error {
	version, err := c.GetNodeVersion(ctx)
	if err != nil {
		return errors.Wrap(err, "testing connectivity")
	}

	log.WithFields(log.Fields{
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

	resp, err := c.client.Do(req)
	if err != nil {
		return respBody, errors.Wrap(err, fmt.Sprintf("unable to request URL %s", callURL.String()))
	}
	if resp == nil {
		return respBody, errors.New("got empty response from the API")
	}
	defer resp.Body.Close()

	respBody, err = io.ReadAll(resp.Body)
	if err != nil {
		return respBody, errors.Wrap(err, "reading response body")
	}

	// return copy of the request
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
