# xDS Demo Client

A simple demonstration client for the Coraza Kubernetes Operator xDS server.

## Overview

This client connects to the xDS server via ADS (Aggregated Discovery Service) and subscribes to ExtensionConfig resources containing Coraza RuleSets. It prints all received rule updates in real-time.

## Building

```bash
cd demo/xds-client
go mod tidy
go build -o xds-client
```

## Usage

### Basic Usage

Connect to xDS server on default port (18000):

```bash
./xds-client
```

### Custom Server Address

```bash
./xds-client -server localhost:18000
```

### Custom Node ID

```bash
./xds-client -node-id my-custom-node
```

## Testing with the Operator

### 1. Start the Operator

In the main project directory:

```bash
# Build the operator
make build

# Run the operator with xDS server enabled
./bin/manager --xds-server-port=18000
```

### 2. Run the Demo Client

In another terminal:

```bash
cd demo/xds-client
./xds-client
```

### 3. Create/Update RuleSets

The client will print any RuleSet updates. Test it by creating a RuleSet in Kubernetes:

```bash
kubectl apply -f ../../config/samples/waf_v1alpha1_ruleset.yaml
```

You should see the client print:

```
=== Received xDS Response ===
Version: <hash>
Type URL: type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig
Resources: 1

--- Resource 1 ---
Name: default/coreruleset-v4-crs-setup
RuleSet Version: <uuid>
RuleSet Name: default/coreruleset-v4-crs-setup
Timestamp: 2026-02-13T19:45:00.123456789Z
Rules Size: 1234 bytes

--- Rules Content ---
SecRule ARGS "@rx .*" "id:1,deny,log,msg:'Test rule'"
--- End Rules ---

ACK sent for version <hash>
```

### 4. Update RuleSets

Modify a ConfigMap referenced by a RuleSet, and watch the client receive push updates in real-time without polling.

## Flags

- `-server string`: xDS server address (default: "localhost:18000")
- `-node-id string`: Node ID for xDS client (default: "coraza-wasm-filter")

## How It Works

1. **Connects** to the xDS server via gRPC
2. **Subscribes** to `type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig` resources
3. **Receives** initial snapshot with all current RuleSets
4. **Streams** updates whenever RuleSets change in Kubernetes
5. **ACKs** each response to acknowledge receipt

## Architecture

```
┌─────────────────┐      gRPC/ADS       ┌──────────────────┐
│   xDS Client    │◄───────stream───────►│   xDS Server     │
│  (this demo)    │                      │  (in operator)   │
└─────────────────┘                      └──────────────────┘
                                                  ▲
                                                  │
                                         Observer notifications
                                                  │
                                         ┌────────┴─────────┐
                                         │  RuleSetCache    │
                                         │  (in-memory)     │
                                         └──────────────────┘
                                                  ▲
                                                  │
                                            Cache updates
                                                  │
                                         ┌────────┴─────────┐
                                         │ RuleSet          │
                                         │ Controller       │
                                         └──────────────────┘
                                                  ▲
                                                  │
                                          Watches K8s
                                                  │
                                         ┌────────┴─────────┐
                                         │  ConfigMaps &    │
                                         │  RuleSets        │
                                         └──────────────────┘
```

## Notes

- The client uses the same node ID as configured in the server ("coraza-wasm-filter" by default)
- This is a broadcast setup - all clients with this node ID receive all RuleSets
- The client automatically ACKs all responses
- Press Ctrl+C to stop the client
