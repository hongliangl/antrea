# Antrea eBPF Observability: Management Discussion Draft

## Proposed Decision

Fund a narrow TCP observability MVP first. It will provide local Pod connect, connection state, RTT,
and retransmission telemetry, enriched with Kubernetes identity and exposed through agent diagnostics
and Prometheus metrics.

DNS behavior, Service and policy correlation, persistent event storage, and UI integration should be
estimated and approved as later increments. They are not required to validate the core value.

## First Deliverable

The first usable release will support Linux, IPv4, non-`hostNetwork` local Pods and provide:

- TCP connect, established, state-change, RTT, and retransmission observations.
- Pod, Namespace, and Node attribution.
- Structured diagnostic output for per-Pod troubleshooting.
- Aggregated Prometheus metrics for TCP signals and collector health.
- A disabled-by-default feature gate, resource bounds, and compatibility checks.

This enables an operator to answer questions such as:

```text
Is this Pod opening connections successfully?
Is its TCP RTT elevated?
Is it experiencing retransmissions or connection churn?
Is the observability component healthy and keeping up with events?
```

It will not identify an application retry, determine an application root cause, or provide an exact
policy decision in the first release.

## Planning Assumptions

- Two engineers are available: one primarily for eBPF/kernel work and one for Antrea agent and tests.
- Engineers have working knowledge of Go and Antrea; kernel/eBPF review support is available.
- The supported environment is agreed before hardening begins.
- Estimate accuracy is approximately plus or minus 30 percent until the compatibility spike closes.
- Estimates include implementation, unit and integration tests, documentation, and review iteration.
- Estimates do not include UI, a new persistent telemetry backend, or cross-team release work.

## TCP MVP Work Breakdown and Effort

| Work package | Deliverable | Effort |
| --- | --- | ---: |
| Hook and compatibility spike | Validate hooks, parent-cgroup coverage, event fields, kernels, and runtimes | 2 engineer-weeks |
| eBPF program completion | Connect, state, RTT, retransmission events; bounded maps and records | 2 engineer-weeks |
| Loader and lifecycle | Feature gate, load, attach, shutdown, restart, and graceful failure | 1.5 engineer-weeks |
| Pod attribution | Pod IP and cgroup identity indexes, churn handling, attribution metrics | 2 engineer-weeks |
| Event processing and output | Decode, enrich, rate-limit, logs or debug output, Prometheus metrics | 2 engineer-weeks |
| Test and compatibility coverage | Unit, integration, load, failure, kernel, and runtime testing | 3 engineer-weeks |
| Documentation and review closure | Configuration, operations guide, design updates, review fixes | 1.5 engineer-weeks |
| Contingency | Kernel and runtime differences discovered during validation | 2 engineer-weeks |
| **Total TCP MVP** | **Product-quality initial TCP capability** | **16 engineer-weeks** |

The existing prototype reduces discovery risk but is not counted as completed product effort. It has
already demonstrated the basic shape of connect and `sockops` collection, ring-buffer ingestion,
initial Pod attribution, logs, and basic metrics.

## Proposed Schedule

Assuming two engineers and timely reviews, the TCP MVP is approximately eight calendar weeks.

| Sprint | Main work | Exit result |
| --- | --- | --- |
| Sprint 1, weeks 1-2 | Compatibility spike; hook and attachment validation; event contract | Go/no-go decision and agreed support matrix |
| Sprint 2, weeks 3-4 | Complete eBPF events, loader lifecycle, and Pod attribution | End-to-end events reliably attributed in test clusters |
| Sprint 3, weeks 5-6 | Metrics, diagnostic output, resource bounds, and failure handling | Operationally usable agent capability |
| Sprint 4, weeks 7-8 | Compatibility, churn and load tests, documentation, and review fixes | Merge-ready TCP MVP |

If only one engineer is assigned, plan for approximately 12 to 16 calendar weeks because kernel and
agent work become sequential and review feedback cannot be absorbed in parallel.

## Later Increments

These are separate scope decisions, not implied parts of the TCP MVP.

| Increment | Result | Additional effort | Main uncertainty |
| --- | --- | ---: | --- |
| DNS behavior | Plain DNS query rate, repeated queries, response codes, inferred timeouts | 5-8 engineer-weeks | Parser scope, TCP DNS, memory and event volume |
| Exact TCP failure diagnostics | Better connect failure and errno coverage using extra hooks | 3-5 engineer-weeks | Stable hook choice across kernels |
| Service and flow correlation | Reliable tuple-based Service and flow context where possible | 6-10 engineer-weeks | NAT timing and data ownership |
| Policy troubleshooting correlation | Join TCP symptoms with authoritative policy evidence | 6-12 engineer-weeks | Correlation fidelity and false claims |
| Persistent API and Flow Aggregator | Searchable events with retention and aggregation | 8-14 engineer-weeks | Storage, API, scaling, and ownership |
| UI / NetOps integration | Workload troubleshooting user experience | Separate estimate | Product design and cross-team dependency |

The ranges are not additive commitments. Each increment needs acceptance criteria before scheduling.

## Delivery Risks and Controls

| Risk | Impact | Control |
| --- | --- | --- |
| Kernel or cgroup differences | Programs fail to load or observe some Pods | Close the support matrix in Sprint 1; fail safely |
| Incorrect Pod attribution | Misleading troubleshooting output | Prefer cgroup identity, validate fallback, expose attribution status |
| High event volume | CPU, memory, or dropped events | Rate limits, bounded buffers, aggregation, and health metrics |
| Prometheus cardinality | Monitoring cost and instability | Keep high-dimensional data in events, not metric labels |
| Scope expansion | Schedule becomes unpredictable | Approve DNS, correlation, storage, and UI as separate increments |
| Maintenance ownership | Feature degrades with kernel changes | Assign code ownership and include compatibility CI where practical |

## Decision Gates

### End of Sprint 1

Proceed only if the agreed environment supports the required hooks, parent-cgroup attachment covers
Pod descendants, events contain sufficient identity and TCP data, and observed overhead is acceptable.

### End of TCP MVP

Decide whether operator feedback justifies investment in DNS, richer failure diagnostics, Antrea
correlation, or a persistent consumer-facing experience.

## Decisions Needed from Management

1. Approve two engineers for an eight-week TCP MVP, with a go/no-go gate after Sprint 1.
2. Confirm that DNS, correlation, event storage, and UI are separately funded increments.
3. Identify the kernel/runtime support expectation and the reviewers who can approve it.
4. Identify the initial consumer: agent troubleshooting, Prometheus alerting, or both.
5. Assign long-term ownership for kernel compatibility and operational support.
