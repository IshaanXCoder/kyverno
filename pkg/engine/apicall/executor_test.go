package apicall

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockValueResolver is a mock implementation of ValueResolver
type MockValueResolver struct {
	mock.Mock
}

func (m *MockValueResolver) ResolveValue(ctx context.Context, valueSource *kyvernov1.ValueSource) (string, error) {
	args := m.Called(ctx, valueSource)
	return args.String(0), args.Error(1)
}

func TestExecutor_addHTTPHeaders(t *testing.T) {
	ctx := context.TODO()
	resolver := new(MockValueResolver)

	e := &executor{
		valueResolver: resolver,
	}

	tests := []struct {
		name        string
		headers     []kyvernov1.HTTPHeader
		setupMock   func()
		wantErr     bool
		errContains string
		wantHeaders map[string]string
	}{
		{
			name: "standard header",
			headers: []kyvernov1.HTTPHeader{
				{Key: "X-Test", Value: "test-value"},
			},
			wantHeaders: map[string]string{"X-Test": "test-value"},
		},
		{
			name: "valueFrom header success",
			headers: []kyvernov1.HTTPHeader{
				{
					Key: "Authorization",
					ValueFrom: &kyvernov1.ValueSource{
						SecretKeyRef: &kyvernov1.SecretKeySelector{
							Name: "my-secret",
							Key:  "token",
						},
					},
				},
			},
			setupMock: func() {
				resolver.On("ResolveValue", ctx, mock.Anything).Return("resolved-token", nil)
			},
			wantHeaders: map[string]string{"Authorization": "resolved-token"},
		},
		{
			name: "valueFrom header error",
			headers: []kyvernov1.HTTPHeader{
				{
					Key: "Authorization",
					ValueFrom: &kyvernov1.ValueSource{
						SecretKeyRef: &kyvernov1.SecretKeySelector{
							Name: "my-secret",
							Key:  "token",
						},
					},
				},
			},
			setupMock: func() {
				resolver.On("ResolveValue", ctx, mock.Anything).Return("", fmt.Errorf("resolve error"))
			},
			wantErr:     true,
			errContains: "failed to resolve header Authorization: resolve error",
		},
		{
			name: "valueFrom header - no resolver",
			headers: []kyvernov1.HTTPHeader{
				{
					Key: "Authorization",
					ValueFrom: &kyvernov1.ValueSource{
						SecretKeyRef: &kyvernov1.SecretKeySelector{
							Name: "my-secret",
							Key:  "token",
						},
					},
				},
			},
			setupMock: func() {
				e.valueResolver = nil
			},
			wantErr:     true,
			errContains: "valueResolver is required to resolve header Authorization from reference",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset resolver and e for each test
			resolver = new(MockValueResolver)
			e.valueResolver = resolver
			if tt.setupMock != nil {
				tt.setupMock()
			}

			req, _ := http.NewRequest("GET", "http://example.com", nil)
			err := e.addHTTPHeaders(ctx, req, tt.headers)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				for k, v := range tt.wantHeaders {
					assert.Equal(t, v, req.Header.Get(k))
				}
			}
			resolver.AssertExpectations(t)
		})
	}
}

func TestExecutor_buildHTTPClient(t *testing.T) {
	ctx := context.TODO()
	resolver := new(MockValueResolver)
	e := &executor{
		valueResolver: resolver,
	}

	tests := []struct {
		name        string
		service     *kyvernov1.ServiceCall
		setupMock   func()
		wantErr     bool
		errContains string
	}{
		{
			name: "caBundle success",
			service: &kyvernov1.ServiceCall{
				CABundle: "pem-encoded-data",
			},
			wantErr:     true, // will fail to parse the dummy data but that's fine for testing the logic flow
			errContains: "failed to parse PEM CA bundle",
		},
		{
			name: "caBundleFrom success",
			service: &kyvernov1.ServiceCall{
				CABundleFrom: &kyvernov1.ValueSource{
					ConfigMapKeyRef: &kyvernov1.ConfigMapKeySelector{
						Name: "ca-cm",
						Key:  "ca.crt",
					},
				},
			},
			setupMock: func() {
				resolver.On("ResolveValue", ctx, mock.Anything).Return("resolved-ca", nil)
			},
			wantErr:     true,
			errContains: "failed to parse PEM CA bundle",
		},
		{
			name: "caBundleFrom error",
			service: &kyvernov1.ServiceCall{
				CABundleFrom: &kyvernov1.ValueSource{
					ConfigMapKeyRef: &kyvernov1.ConfigMapKeySelector{
						Name: "ca-cm",
						Key:  "ca.crt",
					},
				},
			},
			setupMock: func() {
				resolver.On("ResolveValue", ctx, mock.Anything).Return("", fmt.Errorf("resolve error"))
			},
			wantErr:     true,
			errContains: "failed to resolve CA bundle: resolve error",
		},
		{
			name: "caBundleFrom - no resolver",
			service: &kyvernov1.ServiceCall{
				CABundleFrom: &kyvernov1.ValueSource{
					ConfigMapKeyRef: &kyvernov1.ConfigMapKeySelector{
						Name: "ca-cm",
						Key:  "ca.crt",
					},
				},
			},
			setupMock: func() {
				e.valueResolver = nil
			},
			wantErr:     true,
			errContains: "valueResolver is required to resolve CA bundle from reference",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver = new(MockValueResolver)
			e.valueResolver = resolver
			if tt.setupMock != nil {
				tt.setupMock()
			}

			_, err := e.buildHTTPClient(ctx, tt.service)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
			resolver.AssertExpectations(t)
		})
	}
}
