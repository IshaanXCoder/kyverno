package v1

import (
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// ValueSource represents a source for a configuration value.
// It allows referencing values from Secrets or ConfigMaps instead of hardcoding them.
// +kubebuilder:validation:XValidation:rule="(has(self.secretKeyRef) || has(self.configMapKeyRef)) && !(has(self.secretKeyRef) && has(self.configMapKeyRef))", message="exactly one of secretKeyRef or configMapKeyRef must be specified"
type ValueSource struct {
	// SecretKeyRef selects a key from a Secret.
	// +kubebuilder:validation:Optional
	SecretKeyRef *SecretKeySelector `json:"secretKeyRef,omitempty"`

	// ConfigMapKeyRef selects a key from a ConfigMap.
	// +kubebuilder:validation:Optional
	ConfigMapKeyRef *ConfigMapKeySelector `json:"configMapKeyRef,omitempty"`
}

// Validate implements programmatic validation for ValueSource
func (v *ValueSource) Validate(path *field.Path) (errs field.ErrorList) {
	if v.SecretKeyRef != nil && v.ConfigMapKeyRef != nil {
		errs = append(errs, field.Invalid(path, v,
			"exactly one of secretKeyRef or configMapKeyRef must be specified"))
	}
	if v.SecretKeyRef == nil && v.ConfigMapKeyRef == nil {
		errs = append(errs, field.Required(path,
			"either secretKeyRef or configMapKeyRef must be specified"))
	}

	if v.SecretKeyRef != nil {
		errs = append(errs, v.SecretKeyRef.Validate(path.Child("secretKeyRef"))...)
	}
	if v.ConfigMapKeyRef != nil {
		errs = append(errs, v.ConfigMapKeyRef.Validate(path.Child("configMapKeyRef"))...)
	}

	return errs
}

// SecretKeySelector selects a key from a Secret.
type SecretKeySelector struct {
	// Name of the Secret.
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Key within the Secret to select.
	// +kubebuilder:validation:Required
	Key string `json:"key"`

	// Namespace of the Secret. If empty, defaults to the Kyverno namespace.
	// +kubebuilder:validation:Optional
	Namespace string `json:"namespace,omitempty"`
}

// Validate implements programmatic validation for SecretKeySelector
func (s *SecretKeySelector) Validate(path *field.Path) (errs field.ErrorList) {
	if s.Name == "" {
		errs = append(errs, field.Required(path.Child("name"), "secret name is required"))
	}
	if s.Key == "" {
		errs = append(errs, field.Required(path.Child("key"), "secret key is required"))
	}
	return errs
}

// ConfigMapKeySelector selects a key from a ConfigMap.
type ConfigMapKeySelector struct {
	// Name of the ConfigMap.
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Key within the ConfigMap to select.
	// +kubebuilder:validation:Required
	Key string `json:"key"`

	// Namespace of the ConfigMap. If empty, defaults to the Kyverno namespace.
	// +kubebuilder:validation:Optional
	Namespace string `json:"namespace,omitempty"`
}

// Validate implements programmatic validation for ConfigMapKeySelector
func (c *ConfigMapKeySelector) Validate(path *field.Path) (errs field.ErrorList) {
	if c.Name == "" {
		errs = append(errs, field.Required(path.Child("name"), "configmap name is required"))
	}
	if c.Key == "" {
		errs = append(errs, field.Required(path.Child("key"), "configmap key is required"))
	}
	return errs
}
