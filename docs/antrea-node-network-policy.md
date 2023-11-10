# Antrea Node NetworkPolicy

## Table of Contents

<!-- toc -->
- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
- [Limitations](#limitations)
<!-- /toc -->

## Introduction

Node NetworkPolicy is designed to secure the network of Kubernetes Nodes. Starting with v1.15, Antrea introduces support
for Node NetworkPolicy, which provides the control over the network traffic in IP, transport protocol, and port grains.

This guide demonstrates how to configure Node NetworkPolicy.

## Prerequisites

Node NetworkPolicy was introduced in v1.15 as an alpha feature and is disabled by default. A feature gate, `NodeNetworkPolicy`,
must be enabled in antrea-agent.conf in the `antrea-config` ConfigMap. An example configuration is as below:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: antrea-config
  namespace: kube-system
data:
  antrea-agent.conf: |
    featureGates:
      NodeNetworkPolicy: true
```

Alternatively, you can use the following helm installation command to configure the above options:

```bash
helm install antrea antrea/antrea --namespace kube-system --set featureGates.NodeNetworkPolicy=true
```

## Usage

Similar to layer 7 NetworkPolicy, there is no separate resource type for Node NetworkPolicy. It is one type of Antrea-native
policy applied to Kubernetes Nodes by specifying nodeSelector in the global `appliedTo` (not per-rule appliedTo). Other
fields remain the same as Antrea NetworkPolicy applied to Pods.

An example Node NetworkPolicy that blocks ingress traffic from Pods with label `app=client` to Nodes with label
`kubernetes.io/hostname: k8s-node-control-plane`:

```yaml
apiVersion: crd.antrea.io/v1beta1
kind: ClusterNetworkPolicy
metadata:
  name: ingress-drop-pod-to-node
spec:
  priority: 5
  tier: application
  appliedTo:
    - nodeSelector:
        matchLabels:
          kubernetes.io/hostname: k8s-node-control-plane
  ingress:
    - name: drop-80
      action: Drop
      from:
        - podSelector:
            matchLabels:
              app: client
      ports:
        - protocol: TCP
          port: 80
```

An example Node NetworkPolicy that blocks egress traffic from Nodes with the label `kubernetes.io/hostname: k8s-node-control-plane`
to Nodes with the label `kubernetes.io/hostname: k8s-node-worker-1` and some IP blocks:

```yaml
apiVersion: crd.antrea.io/v1beta1
kind: ClusterNetworkPolicy
metadata:
  name: egress-drop-node-to-node
spec:
  priority: 5
  tier: application
  appliedTo:
    - nodeSelector:
        matchLabels:
          kubernetes.io/hostname: k8s-node-control-plane
  egress:
    - name: drop-22
      action: Drop
      to:
        - nodeSelector:
            matchLabels:
              kubernetes.io/hostname: k8s-node-worker-1
        - ipBlock:
            cidr: 192.168.77.0/24
      ports:
        - protocol: TCP
          port: 22
```

## Limitations

- This feature is currently only supported for Nodes running Linux.
- The policies applied to Nodes can be only specified in global `appliedTo` field, not in per-rule `appliedTo`, a `Group`
  or a `ClusterGroup`.
- Policies applied to Nodes can be only specified in `ClusterNetworkPolicy`, not in `NetworkPolicy`.
- Policies applied to Nodes cannot be applied to Pods at the same time.
- FQDN in Node NetworkPolicy is not supported at this moment.
- Layer 7 NetworkPolicy in Node NetworkPolicy is not supported at this moment.
- With misconfiguration, it is possible to block traffic between Nodes and the API server, causing the Node to be unresponsive
  or blocking all traffic to/from the cluster. Please exercise caution when configuring Node NetworkPolicy.
- For egress traffic, the action `Reject` defaults to `Drop`.
