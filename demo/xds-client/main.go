/*
Copyright 2026 Shane Utt.

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

package main

import (
	"context"
	"flag"
	"io"
	"log"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	xdsv1 "github.com/networking-incubator/coraza-kubernetes-operator/pkg/xds/v1"
)

const (
	// DefaultNodeID matches the server's broadcast node ID
	DefaultNodeID = "coraza-wasm-filter"
)

func main() {
	var serverAddr string
	var nodeID string

	flag.StringVar(&serverAddr, "server", "localhost:18000", "xDS server address")
	flag.StringVar(&nodeID, "node-id", DefaultNodeID, "Node ID for xDS client")
	flag.Parse()

	log.Printf("Starting xDS client...")
	log.Printf("  Server: %s", serverAddr)
	log.Printf("  Node ID: %s", nodeID)

	// Connect to xDS server
	conn, err := grpc.NewClient(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect to xDS server: %v", err)
	}
	defer conn.Close()

	// Create ADS client
	client := discoveryv3.NewAggregatedDiscoveryServiceClient(conn)

	// Start streaming
	ctx := context.Background()
	stream, err := client.StreamAggregatedResources(ctx)
	if err != nil {
		log.Fatalf("Failed to create stream: %v", err)
	}

	// Create node information
	node := &corev3.Node{
		Id:      nodeID,
		Cluster: "demo-cluster",
	}

	// Send initial subscription request for ExtensionConfig resources
	initialReq := &discoveryv3.DiscoveryRequest{
		Node:    node,
		TypeUrl: resource.ExtensionConfigType,
	}

	log.Printf("Subscribing to %s resources...", resource.ExtensionConfigType)
	if err := stream.Send(initialReq); err != nil {
		log.Fatalf("Failed to send initial request: %v", err)
	}

	// Receive and process responses
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			log.Println("Stream closed by server")
			break
		}
		if err != nil {
			log.Fatalf("Failed to receive response: %v", err)
		}

		log.Printf("\n=== Received xDS Response ===")
		log.Printf("Version: %s", resp.VersionInfo)
		log.Printf("Type URL: %s", resp.TypeUrl)
		log.Printf("Nonce: %s", resp.Nonce)
		log.Printf("Resources: %d", len(resp.Resources))

		// Process each resource
		for i, res := range resp.Resources {
			log.Printf("\n--- Resource %d ---", i+1)

			// Parse ExtensionConfig
			var extConfig corev3.TypedExtensionConfig
			if err := res.UnmarshalTo(&extConfig); err != nil {
				log.Printf("Failed to unmarshal ExtensionConfig: %v", err)
				continue
			}

			log.Printf("Name: %s", extConfig.Name)

			// Extract the RuleSet from TypedConfig
			if extConfig.TypedConfig != nil {
				var ruleSet xdsv1.RuleSet
				if err := extConfig.TypedConfig.UnmarshalTo(&ruleSet); err != nil {
					log.Printf("Failed to unmarshal RuleSet: %v", err)
					continue
				}

				log.Printf("RuleSet Version: %s", ruleSet.Version)
				log.Printf("RuleSet Name: %s", ruleSet.Name)
				log.Printf("Timestamp: %s", ruleSet.Timestamp)
				log.Printf("Rules Size: %d bytes", len(ruleSet.Rules))
				log.Printf("\n--- Rules Content ---")
				log.Printf("%s", string(ruleSet.Rules))
				log.Printf("--- End Rules ---\n")
			}
		}

		// ACK the response
		ackReq := &discoveryv3.DiscoveryRequest{
			Node:          node,
			TypeUrl:       resp.TypeUrl,
			VersionInfo:   resp.VersionInfo,
			ResponseNonce: resp.Nonce,
		}

		if err := stream.Send(ackReq); err != nil {
			log.Fatalf("Failed to send ACK: %v", err)
		}
		log.Printf("ACK sent for version %s", resp.VersionInfo)
	}
}
