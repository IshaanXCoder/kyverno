package apicall

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/go-logr/logr"
	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	"github.com/kyverno/kyverno/pkg/tracing"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

type Executor interface {
	Execute(context.Context, *kyvernov1.APICall) ([]byte, error)
}

type executor struct {
	logger        logr.Logger
	name          string
	client        ClientInterface
	config        APICallConfiguration
	valueResolver ValueResolver
}

func NewExecutor(
	logger logr.Logger,
	name string,
	client ClientInterface,
	apiCallConfig APICallConfiguration,
	valueResolver ValueResolver,
) *executor {
	return &executor{
		logger:        logger,
		name:          name,
		client:        client,
		config:        apiCallConfig,
		valueResolver: valueResolver,
	}
}

func (a *executor) Execute(ctx context.Context, call *kyvernov1.APICall) ([]byte, error) {
	if call.URLPath != "" {
		return a.executeK8sAPICall(ctx, call.URLPath, call.Method, call.Data)
	}
	return a.executeServiceCall(ctx, call)
}

func (a *executor) executeK8sAPICall(ctx context.Context, path string, method kyvernov1.Method, data []kyvernov1.RequestData) ([]byte, error) {
	requestData, err := a.buildRequestData(data)
	if err != nil {
		return nil, err
	}
	jsonData, err := a.client.RawAbsPath(ctx, path, string(method), requestData)
	if err != nil {
		return nil, fmt.Errorf("failed to %v resource with raw url\n: %s: %v", method, path, err)
	}
	a.logger.V(4).Info("executed APICall", "name", a.name, "path", path, "method", method, "len", len(jsonData))
	return jsonData, nil
}

func (a *executor) executeServiceCall(ctx context.Context, apiCall *kyvernov1.APICall) ([]byte, error) {
	if apiCall.Service == nil {
		return nil, fmt.Errorf("missing service for APICall %s", a.name)
	}

	client, err := a.buildHTTPClient(ctx, apiCall.Service)
	if err != nil {
		return nil, err
	}

	req, err := a.buildHTTPRequest(ctx, apiCall)
	if err != nil {
		return nil, fmt.Errorf("failed to build HTTP request for APICall %s: %w", a.name, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute HTTP request for APICall %s: %w", a.name, err)
	}
	defer resp.Body.Close()
	var w http.ResponseWriter

	if a.config.maxAPICallResponseLength != 0 {
		resp.Body = http.MaxBytesReader(w, resp.Body, a.config.maxAPICallResponseLength)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, err := io.ReadAll(resp.Body)
		if err == nil {
			return nil, fmt.Errorf("HTTP %s: %s", resp.Status, string(b))
		}

		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if _, ok := err.(*http.MaxBytesError); ok {
			return nil, fmt.Errorf("response length must be less than max allowed response length of %d", a.config.maxAPICallResponseLength)
		} else {
			return nil, fmt.Errorf("failed to read data from APICall %s: %w", a.name, err)
		}
	}

	a.logger.V(4).Info("executed service APICall", "name", a.name, "len", len(body))
	return body, nil
}

func (a *executor) buildHTTPRequest(ctx context.Context, apiCall *kyvernov1.APICall) (*http.Request, error) {
	if apiCall.Service == nil {
		return nil, fmt.Errorf("missing service")
	}

	if apiCall.Method != "GET" && apiCall.Method != "POST" {
		return nil, fmt.Errorf("invalid request type %s for APICall %s", apiCall.Method, a.name)
	}

	var data io.Reader = nil
	if apiCall.Method == "POST" {
		var err error
		data, err = a.buildRequestData(apiCall.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to build request data for APICall %s: %w", a.name, err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, string(apiCall.Method), apiCall.Service.URL, data)
	if err != nil {
		return nil, fmt.Errorf("failed to build request for APICall %s: %w", a.name, err)
	}

	if err := a.addHTTPHeaders(ctx, req, apiCall.Service.Headers); err != nil {
		return nil, fmt.Errorf("failed to add headers for APICall %s: %w", a.name, err)
	}

	return req, nil
}

func (a *executor) addHTTPHeaders(ctx context.Context, req *http.Request, headers []kyvernov1.HTTPHeader) error {
	for _, header := range headers {
		var value string
		var err error

		// Resolve value from Secret/ConfigMap if valueFrom is specified
		if header.ValueFrom != nil {
			if a.valueResolver != nil {
				value, err = a.valueResolver.ResolveValue(ctx, header.ValueFrom)
				if err != nil {
					return fmt.Errorf("failed to resolve header %s: %w", header.Key, err)
				}
			} else {
				return fmt.Errorf("valueResolver is required to resolve header %s from reference", header.Key)
			}
		} else {
			value = header.Value
		}

		req.Header.Add(header.Key, value)
	}

	if req.Header.Get("Authorization") == "" {
		token := a.getToken()
		if token != "" {
			req.Header.Add("Authorization", "Bearer "+token)
		}
	}

	return nil
}

func (a *executor) getToken() string {
	fileName := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	b, err := os.ReadFile(fileName)
	if err != nil {
		a.logger.Info("failed to read service account token", "path", fileName)
		return ""
	}

	return string(b)
}

func (a *executor) buildHTTPClient(ctx context.Context, service *kyvernov1.ServiceCall) (*http.Client, error) {
	var caBundle string
	var err error

	// Resolve CA bundle from Secret/ConfigMap if caBundleFrom is specified
	if service.CABundleFrom != nil {
		if a.valueResolver != nil {
			caBundle, err = a.valueResolver.ResolveValue(ctx, service.CABundleFrom)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve CA bundle: %w", err)
			}
		} else {
			return nil, fmt.Errorf("valueResolver is required to resolve CA bundle from reference")
		}
	} else {
		caBundle = service.CABundle
	}

	if service == nil || caBundle == "" {
		return http.DefaultClient, nil
	}

	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM([]byte(caBundle)); !ok {
		return nil, fmt.Errorf("failed to parse PEM CA bundle for APICall %s", a.name)
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    caCertPool,
			MinVersion: tls.VersionTLS12,
		},
	}
	return &http.Client{
		Transport: tracing.Transport(transport, otelhttp.WithFilter(tracing.RequestFilterIsInSpan)),
	}, nil
}

func (a *executor) buildRequestData(data []kyvernov1.RequestData) (io.Reader, error) {
	dataMap := make(map[string]interface{})
	for _, d := range data {
		dataMap[d.Key] = d.Value
	}

	buffer := new(bytes.Buffer)
	if err := json.NewEncoder(buffer).Encode(dataMap); err != nil {
		return nil, fmt.Errorf("failed to encode HTTP POST data %v for APICall %s: %w", dataMap, a.name, err)
	}

	return buffer, nil
}
