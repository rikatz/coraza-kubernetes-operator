# ------------------------------------------------------------------------------
# Vars
# ------------------------------------------------------------------------------

SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

CONTAINER_TOOL ?= docker

KIND_CLUSTER_NAME ?= coraza-kubernetes-operator-integration
ISTIO_VERSION ?= 1.28.2

CONTROLLER_MANAGER_CONTAINER_IMAGE_BASE ?= ghcr.io/networking-incubator/coraza-kubernetes-operator
CONTROLLER_MANAGER_CONTAINER_IMAGE_TAG ?= dev
CONTROLLER_MANAGER_CONTAINER_IMAGE ?= ${CONTROLLER_MANAGER_CONTAINER_IMAGE_BASE}:${CONTROLLER_MANAGER_CONTAINER_IMAGE_TAG}

# ------------------------------------------------------------------------------
# General
# ------------------------------------------------------------------------------

.PHONY: help
help:
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: all
all: build

# ------------------------------------------------------------------------------
# Build
# ------------------------------------------------------------------------------

.PHONY: build
build: manifests generate proto fmt vet lint
	go build -o bin/manager cmd/main.go

.PHONY: build.image
build.image:
	$(CONTAINER_TOOL) build -t ${CONTROLLER_MANAGER_CONTAINER_IMAGE} .

.PHONY: build.installer
build.installer: manifests generate kustomize
	mkdir -p dist
	cd config/manager && "$(KUSTOMIZE)" edit set image controller=${CONTROLLER_MANAGER_CONTAINER_IMAGE}
	"$(KUSTOMIZE)" build config/default > dist/install.yaml

# ------------------------------------------------------------------------------
# Deployment
# ------------------------------------------------------------------------------

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize
	@out="$$( "$(KUSTOMIZE)" build config/crd 2>/dev/null || true )"; \
	if [ -n "$$out" ]; then echo "$$out" | "$(KUBECTL)" apply -f -; else echo "No CRDs to install; skipping."; fi

.PHONY: uninstall
uninstall: manifests kustomize
	@out="$$( "$(KUSTOMIZE)" build config/crd 2>/dev/null || true )"; \
	if [ -n "$$out" ]; then echo "$$out" | "$(KUBECTL)" delete --ignore-not-found=$(ignore-not-found) -f -; else echo "No CRDs to delete; skipping."; fi

.PHONY: deploy
deploy: manifests kustomize
	cd config/manager && "$(KUSTOMIZE)" edit set image controller=${CONTROLLER_MANAGER_CONTAINER_IMAGE}
	"$(KUSTOMIZE)" build config/default | "$(KUBECTL)" apply -f -

.PHONY: undeploy
undeploy: kustomize
	"$(KUSTOMIZE)" build config/default | "$(KUBECTL)" delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: run
run: manifests generate fmt vet
	go run ./cmd/main.go

# ------------------------------------------------------------------------------
# Development
# ------------------------------------------------------------------------------

.PHONY: manifests
manifests: controller-gen
	"$(CONTROLLER_GEN)" rbac:roleName=coraza-controller-manager crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen
	"$(CONTROLLER_GEN)" object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: proto
proto: protoc protoc-gen-go protoc-gen-go-grpc
	"$(PROTOC)" \
		--proto_path=api/xds/v1 \
		--go_out=pkg/xds/v1 \
		--go_opt=paths=source_relative \
		--go-grpc_out=pkg/xds/v1 \
		--go-grpc_opt=paths=source_relative \
		--plugin=protoc-gen-go="$(PROTOC_GEN_GO)" \
		--plugin=protoc-gen-go-grpc="$(PROTOC_GEN_GO_GRPC)" \
		api/xds/v1/ruleset.proto

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: lint
lint: golangci-lint
	"$(GOLANGCI_LINT)" run --build-tags integration ./...

.PHONY: lint.fix
lint.fix: golangci-lint
	"$(GOLANGCI_LINT)" run --fix --build-tags integration ./...

.PHONY: lint.config
lint.config: golangci-lint
	"$(GOLANGCI_LINT)" config verify

# ------------------------------------------------------------------------------
# Test Cluster
# ------------------------------------------------------------------------------

.PHONY: cluster.kind
cluster.kind:
	ISTIO_VERSION=${ISTIO_VERSION} python3 hack/kind_cluster.py setup

.PHONY: cluster.load-images
cluster.load-images:
	@$(CONTAINER_TOOL) exec ${KIND_CLUSTER_NAME}-control-plane crictl rmi ${CONTROLLER_MANAGER_CONTAINER_IMAGE} 2>/dev/null || true
	$(KIND) load docker-image ${CONTROLLER_MANAGER_CONTAINER_IMAGE} --name ${KIND_CLUSTER_NAME}

.PHONY: clean.cluster.kind
clean.cluster.kind:
	python3 hack/kind_cluster.py delete --name ${KIND_CLUSTER_NAME}

# -------------------------------------------------------------------------------
# Testing
# -------------------------------------------------------------------------------

.PHONY: test
test: generate setup-envtest
	ISTIO_VERSION=${ISTIO_VERSION} KUBEBUILDER_ASSETS="$$($(SETUP_ENVTEST) use -p path)" go test -v ./...

.PHONY: test.coverage
test.coverage: generate setup-envtest
	@echo "Running tests with coverage..."
	@ISTIO_VERSION=${ISTIO_VERSION} KUBEBUILDER_ASSETS="$$($(SETUP_ENVTEST) use -p path)" go test -v ./... -coverprofile=coverage.out -covermode=atomic
	@echo "Coverage by package:"
	@go tool cover -func=coverage.out | grep -v "total:" || true
	@echo "Total coverage:"
	@total=$$(go tool cover -func=coverage.out | grep total | awk '{print $$3}' | sed 's/%//'); \
	echo "Total: $${total}%"

.PHONY: test.integration
test.integration:
	go clean -testcache
	KIND_CLUSTER_NAME=${KIND_CLUSTER_NAME} ISTIO_VERSION=${ISTIO_VERSION} go test -tags=integration ./test/integration/... -v

# -------------------------------------------------------------------------------
# Dependencies
# -------------------------------------------------------------------------------

LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p "$(LOCALBIN)"

KUBECTL ?= kubectl
KIND ?= kind
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint
SETUP_ENVTEST ?= $(LOCALBIN)/setup-envtest
PROTOC ?= $(LOCALBIN)/protoc
PROTOC_GEN_GO ?= $(LOCALBIN)/protoc-gen-go
PROTOC_GEN_GO_GRPC ?= $(LOCALBIN)/protoc-gen-go-grpc

KUSTOMIZE_VERSION ?= v5.7.1
CONTROLLER_TOOLS_VERSION ?= v0.19.0
GOLANGCI_LINT_VERSION ?= v2.5.0
SETUP_ENVTEST_VERSION ?= latest
PROTOC_VERSION ?= 29.5
PROTOC_GEN_GO_VERSION ?= v1.36.5
PROTOC_GEN_GO_GRPC_VERSION ?= v1.6.0

.PHONY: kustomize
kustomize: $(KUSTOMIZE)
$(KUSTOMIZE): $(LOCALBIN)
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5,$(KUSTOMIZE_VERSION))

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN)
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT)
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

.PHONY: setup-envtest
setup-envtest: $(SETUP_ENVTEST)
$(SETUP_ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(SETUP_ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(SETUP_ENVTEST_VERSION))

.PHONY: protoc
protoc: $(PROTOC)
$(PROTOC): $(LOCALBIN)
	@[ -f "$(PROTOC)-$(PROTOC_VERSION)" ] && [ "$$(readlink -- "$(PROTOC)" 2>/dev/null)" = "$(PROTOC)-$(PROTOC_VERSION)" ] || { \
	set -e; \
	echo "Downloading protoc $(PROTOC_VERSION)" ;\
	rm -f "$(PROTOC)" ;\
	OS=$$(uname -s | tr '[:upper:]' '[:lower:]'); \
	ARCH=$$(uname -m); \
	case $$ARCH in x86_64) ARCH="x86_64";; aarch64|arm64) ARCH="aarch_64";; esac; \
	PROTOC_ZIP="protoc-$(PROTOC_VERSION)-$${OS}-$${ARCH}.zip"; \
	curl -Lo "$(LOCALBIN)/$$PROTOC_ZIP" "https://github.com/protocolbuffers/protobuf/releases/download/v$(PROTOC_VERSION)/$$PROTOC_ZIP"; \
	unzip -o "$(LOCALBIN)/$$PROTOC_ZIP" -d "$(LOCALBIN)/protoc-$(PROTOC_VERSION)" bin/protoc; \
	rm "$(LOCALBIN)/$$PROTOC_ZIP"; \
	mv "$(LOCALBIN)/protoc-$(PROTOC_VERSION)/bin/protoc" "$(PROTOC)-$(PROTOC_VERSION)"; \
	rm -rf "$(LOCALBIN)/protoc-$(PROTOC_VERSION)"; \
	}; \
	ln -sf "$$(realpath "$(PROTOC)-$(PROTOC_VERSION)")" "$(PROTOC)"

.PHONY: protoc-gen-go
protoc-gen-go: $(PROTOC_GEN_GO)
$(PROTOC_GEN_GO): $(LOCALBIN)
	$(call go-install-tool,$(PROTOC_GEN_GO),google.golang.org/protobuf/cmd/protoc-gen-go,$(PROTOC_GEN_GO_VERSION))

.PHONY: protoc-gen-go-grpc
protoc-gen-go-grpc: $(PROTOC_GEN_GO_GRPC)
$(PROTOC_GEN_GO_GRPC): $(LOCALBIN)
	$(call go-install-tool,$(PROTOC_GEN_GO_GRPC),google.golang.org/grpc/cmd/protoc-gen-go-grpc,$(PROTOC_GEN_GO_GRPC_VERSION))

define go-install-tool
@[ -f "$(1)-$(3)" ] && [ "$$(readlink -- "$(1)" 2>/dev/null)" = "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f "$(1)" ;\
GOBIN="$(LOCALBIN)" go install $${package} ;\
mv "$(LOCALBIN)/$$(basename "$(1)")" "$(1)-$(3)" ;\
} ;\
ln -sf "$$(realpath "$(1)-$(3)")" "$(1)"
endef

define gomodver
$(shell go list -m -f '{{if .Replace}}{{.Replace.Version}}{{else}}{{.Version}}{{end}}' $(1) 2>/dev/null)
endef
