package apicall

import (
	"context"
	"testing"

	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestResolveValue(t *testing.T) {
	ctx := context.TODO()

	// Setup fake client with some data
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"my-key": []byte("secret-value"),
		},
	}

	secretInKyverno := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-secret",
			Namespace: "kyverno",
		},
		Data: map[string][]byte{
			"my-key": []byte("kyverno-secret-value"),
		},
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-configmap",
			Namespace: "default",
		},
		Data: map[string]string{
			"my-key": "configmap-value",
		},
	}

	client := fake.NewSimpleClientset(secret, secretInKyverno, configMap)
	resolver := NewValueResolver(client, "kyverno")

	tests := []struct {
		name        string
		valueSource *kyvernov1.ValueSource
		want        string
		wantErr     bool
		errContains string
	}{
		{
			name:        "nil value source",
			valueSource: nil,
			wantErr:     true,
			errContains: "valueSource is nil",
		},
		{
			name: "secret key ref success",
			valueSource: &kyvernov1.ValueSource{
				SecretKeyRef: &kyvernov1.SecretKeySelector{
					Name:      "my-secret",
					Namespace: "default",
					Key:       "my-key",
				},
			},
			want: "secret-value",
		},
		{
			name: "secret key ref default namespace",
			valueSource: &kyvernov1.ValueSource{
				SecretKeyRef: &kyvernov1.SecretKeySelector{
					Name: "my-secret",
					Key:  "my-key",
				},
			},
			want: "kyverno-secret-value",
		},
		{
			name: "secret not found",
			valueSource: &kyvernov1.ValueSource{
				SecretKeyRef: &kyvernov1.SecretKeySelector{
					Name:      "non-existent",
					Namespace: "default",
					Key:       "my-key",
				},
			},
			wantErr:     true,
			errContains: "failed to get secret",
		},
		{
			name: "secret key not found",
			valueSource: &kyvernov1.ValueSource{
				SecretKeyRef: &kyvernov1.SecretKeySelector{
					Name:      "my-secret",
					Namespace: "default",
					Key:       "non-existent-key",
				},
			},
			wantErr:     true,
			errContains: "key non-existent-key not found in secret",
		},
		{
			name: "configmap key ref success",
			valueSource: &kyvernov1.ValueSource{
				ConfigMapKeyRef: &kyvernov1.ConfigMapKeySelector{
					Name:      "my-configmap",
					Namespace: "default",
					Key:       "my-key",
				},
			},
			want: "configmap-value",
		},
		{
			name: "configmap not found",
			valueSource: &kyvernov1.ValueSource{
				ConfigMapKeyRef: &kyvernov1.ConfigMapKeySelector{
					Name:      "non-existent",
					Namespace: "default",
					Key:       "my-key",
				},
			},
			wantErr:     true,
			errContains: "failed to get configmap",
		},
		{
			name: "configmap key not found",
			valueSource: &kyvernov1.ValueSource{
				ConfigMapKeyRef: &kyvernov1.ConfigMapKeySelector{
					Name:      "my-configmap",
					Namespace: "default",
					Key:       "non-existent-key",
				},
			},
			wantErr:     true,
			errContains: "key non-existent-key not found in configmap",
		},
		{
			name:        "no reference specified",
			valueSource: &kyvernov1.ValueSource{},
			wantErr:     true,
			errContains: "no valid reference found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolver.ResolveValue(ctx, tt.valueSource)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
