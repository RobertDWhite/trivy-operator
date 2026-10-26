# Draft bounded vulnerability report persistence

This implementation is a candidate, not a production rollout. Complete integration and live acceptance below before changing the deployed image.

The writer retains ordinary reports that fit within512KiB. Larger reports are split into contiguous, complete vulnerability lists; every data part includes the same scan/artifact header and its own severity summary. Deterministic names include root identity, content generation and part index. All data parts are written before the original report name is updated to a commit manifest. The manifest retains the full severity summary, an empty inline finding list, an explicit `report-mode: manifest` annotation and a JSON list of referenced part names. No findings, fields, severities or unfixed results are discarded.

The generation is SHA256 of the typed report JSON with the observation timestamp cleared, so retries of the same scan target the same objects. Readers verify part presence/order, generation, artifact/scanner headers, per-part summaries, total summary and reconstructed content hash. Missing/corrupt sets and orphan parts cannot satisfy workload coverage. Metrics assemble complete logical reports once; data parts and obsolete generations are not independently counted. `trivy_vulnerability_report_incomplete_sets` exposes rejected sets. A later small report clears protocol annotations; old parts remain invisible to readers.

Data parts retain the original workload ownership and report TTL annotations. This is not a guarantee that stale parts are promptly collected: verify the deployed TTL controller and interrupted cleanup/expiry behavior before rollout. Unknown external consumers must follow the manifest references; reading only its inline finding list is not a complete report. The scan archive remains independent and keeps the original full scanner output.

## Validation performed

- Lossless reconstruction, serialized object size including escaped Unicode, all severity classes and unfixed entries.
- Stable names on retry, partial-write recovery, missing parts/manifests, mixed generations, corrupt contents/headers, wrong summaries and duplicate references.
- Replacement by another generation and by an ordinary small report without double counting.
- Namespaced/cluster writer tests and actual Prometheus collector tests for complete/incomplete sets.
- Package/controller/metrics tests, race detector and vet.
- Optional private full-report test preserved19398 findings across138 data objects, maximum524266 bytes. Raw input and report details are not committed.

## Required before deployment

1. Make archive CRD coverage distinguish manifests/parts and reject incomplete sets; retain archive-only visibility. Add an incomplete-set alert and verify its route.
2. Validate actual Kubernetes admission/write size and controller retries against an isolated report namespace; fake-client success is insufficient.
3. Prove TTL/owner deletion, partial expiry, interrupted writes and obsolete-part reclamation. Test serialized metadata growth and annotation-size bounds.
4. Verify memory and scrape latency with the largest real reports, plus compatibility of report consumers. Scope findings to the tested runtime architectures.
5. Build, scan and validate the exact operator image, then deploy a controlled canary and prove oversized-write errors cease while totals remain exact. Keep full archive checksums and rollback evidence.

Oversized individual findings or oversized manifest metadata fail explicitly. Exposed-secret/SBOM report partitioning is outside this implementation and must not be claimed fixed by it.

## Annotation size validation

The partitioner validates the Kubernetes aggregate annotation byte limit on the original report, each data part and the final manifest before returning objects to the writer. Object-size budgets alone do not satisfy this independent API constraint. Invalid sets return an error with no objects; tests cover ordinary reports, metadata growth in parts, manifest reference growth, and zero writes for namespace and cluster report writers. Existing annotations added during API updates still remain subject to API admission. This does not complete archive assembly, obsolete-part cleanup, or live API/TTL acceptance gates.
