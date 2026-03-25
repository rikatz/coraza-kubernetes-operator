package framework

import (
	"fmt"
	"os/exec"
)

// -----------------------------------------------------------------------------
// Kubernetes
// -----------------------------------------------------------------------------

// KubeContext returns the kubectl context string for the cluster.
// For kind clusters returns "kind-<name>". For external clusters returns "".
func (f *Framework) KubeContext() string {
	if f.ClusterName == "external" {
		return ""
	}
	return fmt.Sprintf("kind-%s", f.ClusterName)
}

// Kubectl returns an exec.Cmd for running kubectl against the cluster
// in the given namespace.
func (f *Framework) Kubectl(namespace string, args ...string) *exec.Cmd {
	return exec.Command("kubectl", f.kubectlArgs(namespace, args...)...)
}

func (f *Framework) kubectlArgs(namespace string, args ...string) []string {
	cmdArgs := make([]string, 0, len(args)+4)
	if ctx := f.KubeContext(); ctx != "" {
		cmdArgs = append(cmdArgs, "--context", ctx)
	}
	if namespace != "" {
		cmdArgs = append(cmdArgs, "-n", namespace)
	}
	cmdArgs = append(cmdArgs, args...)
	return cmdArgs
}
