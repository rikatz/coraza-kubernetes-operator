/*
Copyright Coraza Kubernetes Operator contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

// -----------------------------------------------------------------------------
// Engine - Target
// -----------------------------------------------------------------------------

// EngineTarget identifies the workload that the Engine protects.
//
// +kubebuilder:validation:XValidation:rule="self.type == 'Gateway' ? has(self.name) : true",message="name is required when type is Gateway"
type EngineTarget struct {
	// type is the type of resource being targeted.
	//
	// Currently only supports "Gateway" mode, utilizing Gateway API resources.
	//
	// +required
	Type EngineTargetType `json:"type,omitempty"`

	// name is the name of the target resource in the same namespace as the
	// Engine. For Gateway targets, the operator derives the workload selector
	// from this name using the GEP-1762 convention
	// (gateway.networking.k8s.io/gateway-name label).
	//
	// Must conform to RFC 1035 label syntax: lowercase alphanumeric or
	// hyphens, must start with a letter and end with an alphanumeric
	// (e.g. "my-gateway", "gw1"). This matches Kubernetes Service naming
	// rules and ensures compatibility with Gateway implementations that
	// derive Service names from the Gateway name.
	//
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:XValidation:rule="!format.dns1035Label().validate(self).hasValue()",message="name must be a valid DNS-1035 label (lowercase, starts with a letter)"
	Name string `json:"name,omitempty"`
}

// -----------------------------------------------------------------------------
// Engine - Target Type
// -----------------------------------------------------------------------------

// EngineTargetType specifies the type of resource an Engine targets.
//
// +kubebuilder:validation:Enum=Gateway
type EngineTargetType string

const (
	// EngineTargetTypeGateway targets a Gateway API Gateway resource.
	EngineTargetTypeGateway EngineTargetType = "Gateway"
)
