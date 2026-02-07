package apicall

import (
	"context"
	"fmt"

	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ValueResolver resolves ValueSource references to actual string values
// by fetching data from Secrets or ConfigMaps
type ValueResolver interface {
	ResolveValue(ctx context.Context, valueSource *kyvernov1.ValueSource) (string, error)
}

type valueResolver struct {
	client           kubernetes.Interface
	kyvernoNamespace string
}

// NewValueResolver creates a new ValueResolver instance
func NewValueResolver(client kubernetes.Interface, kyvernoNamespace string) ValueResolver {
	return &valueResolver{
		client:           client,
		kyvernoNamespace: kyvernoNamespace,
	}
}

// ResolveValue resolves a ValueSource to its actual string value
func (r *valueResolver) ResolveValue(ctx context.Context, valueSource *kyvernov1.ValueSource) (string, error) {
	if valueSource == nil {
		return "", fmt.Errorf("valueSource is nil")
	}

	if valueSource.SecretKeyRef != nil {
		return r.resolveSecretKeyRef(ctx, valueSource.SecretKeyRef)
	}

	if valueSource.ConfigMapKeyRef != nil {
		return r.resolveConfigMapKeyRef(ctx, valueSource.ConfigMapKeyRef)
	}

	return "", fmt.Errorf("no valid reference found in valueSource")
}

// resolveSecretKeyRef fetches a value from a Secret
func (r *valueResolver) resolveSecretKeyRef(ctx context.Context, ref *kyvernov1.SecretKeySelector) (string, error) {
	namespace := ref.Namespace
	if namespace == "" {
		namespace = r.kyvernoNamespace
	}

	secret, err := r.client.CoreV1().Secrets(namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get secret %s/%s: %w", namespace, ref.Name, err)
	}

	value, ok := secret.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("key %s not found in secret %s/%s", ref.Key, namespace, ref.Name)
	}

	return string(value), nil
}

// resolveConfigMapKeyRef fetches a value from a ConfigMap
func (r *valueResolver) resolveConfigMapKeyRef(ctx context.Context, ref *kyvernov1.ConfigMapKeySelector) (string, error) {
	namespace := ref.Namespace
	if namespace == "" {
		namespace = r.kyvernoNamespace
	}

	configMap, err := r.client.CoreV1().ConfigMaps(namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get configmap %s/%s: %w", namespace, ref.Name, err)
	}

	value, ok := configMap.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("key %s not found in configmap %s/%s", ref.Key, namespace, ref.Name)
	}

	return value, nil
}
