# Evaluation report: Ghost Data Still Exists

## How to reproduce

```bash
python3 code/evaluation/main.py -v          # runs the agent on the 32 labelled samples and scores it
python3 code/evaluation/custom_cases.py     # runs the 6 custom evaluation cases
```

The scorer (`code/evaluation/main.py`) compares predicted rows with `dataset/sample_output.csv`. Each step is compared as the tuple (phase, system_id, resource_id, operation, state, evidence_id), so `step_no` and JSON key order are ignored, as the grader does.

| Metric | Definition |
|---|---|
| Case status accuracy | `deletion_status` matches. |
| Exact case accuracy | The whole `steps_json` array is identical, including order. |
| Step precision / recall / F1 | Set overlap of the step tuples. |
| Field accuracy | For predicted steps that align with a gold step on (phase, resource_id, operation), the share whose field matches. |
| Sequence accuracy | Cases where the common steps appear in the same relative order as in gold. |

## Results on the 32 labelled samples (final version)

| Metric | Value |
|---|---|
| Case status accuracy | **32 / 32 = 100.0%** |
| Exact case accuracy (whole `steps_json` identical) | 28 / 32 = 87.5% |
| Step precision | 189 / 190 = 99.5% |
| Step recall | 189 / 193 = 97.9% |
| Step F1 | 98.7% |
| Sequence accuracy | 100.0% |
| Field accuracy: phase / system_id / resource_id / operation / state | 100% each |
| Field accuracy: evidence_id | 100% |

The samples were also the development set, so these numbers are optimistic. The custom cases below test behaviour that the samples don't cover.

### Remaining sample errors (4 steps across 4 cases), and why they remain

| Case | Difference | Reason |
|---|---|---|
| case_04 | missing `account_004` VERIFY_RECORD_ABSENT | The account id never appears in any activity or evidence row. It can't be derived from participant data. |
| case_18, case_20 | missing `audit_record_6645` / `audit_record_5569` VERIFY_RECORD_PRESENT | These record ids appear nowhere in the supplied files. |
| case_23 | `account_9155` predicted instead of `account_410` | Two identifier-free primary profiles were submitted in the same worker window with the same result (FAILED), and neither is ever read back. It's a genuine 50/50 tie, broken deterministically. |

## Full dataset run (518 requests)

| | Count |
|---|---|
| INCOMPLETE | 356 |
| COMPLETE | 152 |
| NOT_APPLICABLE | 10 |
| Steps emitted | 3,263 (722 findings, 722 remediations, 1,819 verifications) |

Structural checks run on `output.csv`:

- 518 rows in input order;
- valid JSON in every row;
- consecutive step numbers;
- phase order respected;
- no cited file captured after the case's `audit_at`;
- every COMPLETE verification cites evidence, except case_63 (see the judgment calls below).

Each group of about 10 requests that shares an `audit_at` cites the snapshot captured for that time (for example `audit_at` 2026-03-05T12:00 cites evidence_43). This is a useful sanity signal that resources were linked to the right requests.

## Custom evaluation cases (team-written)

`code/evaluation/custom_cases.py` builds new requests by perturbing real ones. Each one checks a property that follows from the challenge rules.

| # | Case | Expected behaviour | Result |
|---|---|---|---|
| C1 | case_12 re-filed with the user's **previous e-mail** (`minjun.kim90@…`, from `user_audit_log.csv`) | Same subject and an identical audit to the current-e-mail request | PASS |
| C2 | Same request with the e-mail in **UPPER CASE** | Identical audit | PASS |
| C3 | case_11 with `audit_at` moved **before** the 2026-10-01 handover snapshot | evidence_03 is not cited, nothing captured after `audit_at` is cited, and the answer is rebuilt from earlier evidence | PASS |
| C4 | A deletion request reworded as *"send me a copy… don't delete anything"* | NOT_APPLICABLE with `[]` | PASS |
| C5 | case_35 (g.silva76@gmail.com), where the search console also shows **g.silva76.jr@gmail.com** | search_428 is reported and the look-alike search_1874 is not | PASS |
| C6 | case_63, where the data catalog links marketing_001 to the requester but the **screenshot shows a different person** | marketing_001 is not attributed to the requester | PASS |

## Ablation study: what each technique contributes

`python3 code/evaluation/ablation.py` switches each technique off in turn. It re-scores the 32 labelled samples and counts how many of the 518 evaluation answers change.

| Variant | Status acc. | Step F1 | Exact cases | Eval answers changed (status / steps) |
|---|---|---|---|---|
| **Full agent** | **100.0%** | **0.987** | **28/32** | - |
| - identity history (old e-mails/phones/hashes) | 90.6% | 0.895 | 25/32 | 111 / 150 |
| - worker-run linking (identifier-free records) | 100.0% | 0.925 | 10/32 | 0 / 369 |
| - status/result compatibility | 100.0% | 0.971 | 27/32 | 0 / 76 |
| - evidence co-occurrence | 100.0% | 0.982 | 26/32 | 0 / 3 |
| - policy-action chain timing | 100.0% | 0.977 | 26/32 | 0 / 14 |
| - proof-aware refinement pass | 100.0% | 0.982 | 26/32 | 0 / 49 |
| - replica drift (primary table only) | 96.9% | 0.971 | 26/32 | 2 / 11 |
| - snapshot absence proof | 100.0% | 0.971 | 25/32 | 0 / 68 |
| - catalog contradiction check | 100.0% | 0.987 | 28/32 | 1 / 1 |

What this shows:

- **Identity history decides statuses.** Without old e-mails, phones and hashes, 111 of the 518 answers change status. One in five requests uses an identifier the user no longer has.
- **Worker-run linking decides steps.** Removing it leaves statuses unchanged, but it alters the steps of 369 answers and drops exact-case accuracy from 28/32 to 10/32. Deleted accounts and anonymized analytics carry no identifiers, so without it they vanish from the verification plan.
- **The disambiguation heuristics** (status compatibility, co-occurrence, chain timing, proof refinement) each fix a smaller set of attributions: 3 to 76 answers each. None of them changes a status.
- **Replica drift and the catalog check** affect few answers, but those answers flip between COMPLETE and INCOMPLETE. These are exactly the traps the challenge describes: a replica still holding a deleted profile, and a catalog link the record itself contradicts.

## Evidence trail and confidence (explainability)

Every run also writes `audit_trail.json`. For each request it records:

- the subject that was resolved, and whether it was matched by the current or a historical e-mail (with the `audit_id`);
- every resource considered: data category, the `deletion_rules.csv` rule applied, how it was linked (identifiers, catalog, worker run, recreation path), how ambiguity was resolved, its state at `audit_at`, the evidence file that proves it and when that file was captured, and the decision;
- a confidence level with its reasons;
- the emitted steps.

`python3 code/explain.py case_49` prints the trail for one case. `python3 code/explain.py --low` lists the low-confidence cases.

The confidence level reflects how each record was attributed to the request:

| Level | Meaning | Eval cases (518) |
|---|---|---|
| high | Every record is linked by the subject's own identifiers, or deduced without any ambiguity. | 218 (incl. all 10 NOT_APPLICABLE) |
| medium | At least one identifier-free record was deduced from several candidate requests, or a record's state comes from an activity status check. | 165 |
| low | At least one record was placed by a deterministic tie-break (95 records), by elimination against a tie-broken record (58), or nothing attributable was found (case_63). | 135 |

None of the tie-broken records drives a finding. Every one is in a compliant state (for example an account that is absent either way), so **no status depends on a tie-break**. The uncertainty is about which resource ID appears in a verification step, not about whether the deletion is complete.

Calibration on the labelled samples:

| Confidence | Sample cases | Exact-case accuracy |
|---|---|---|
| high | 17 | 100% |
| medium | 9 | 67% |
| low | 6 | 83% |

High-confidence answers were always exactly right. The medium misses are case_04, case_18 and case_20, whose missing IDs don't exist in the data at all (see above), so they aren't attribution errors. The low bucket holds the one real wrong attribution (case_23). The sample is small, so the medium/low ordering isn't meaningful.

## Failures found and improvements made

| Iteration | Change | Status acc. | Step F1 |
|---|---|---|---|
| v1 | First end-to-end pipeline: parse all evidence, link by identifiers, take the latest state, apply rules | 81.3% | 0.817 |
| v2 | **Intent classifier fix.** Free-text sample requests ("my profile still appears…", "copies…") were wrongly NOT_APPLICABLE. Requests now default to deletion intent unless an explicit non-deletion purpose or refusal is stated. | 96.9% | 0.933 |
| v3 | **Snapshot scope and absence proof.** Rows missing from full snapshots (profile tables, empty `customer_profiles` collections) prove absence. Explicit reads beat inventory absence. Post-audit retained records are used only in post-remediation verification. | 100% | 0.971 |
| v4 | **Linking records with no identifiers.** Deleted accounts and anonymized analytics carry no identifiers, so they're linked through the deletion-worker run around `reported_at`. Disambiguation uses: (a) the primary-profile result must match the workflow claim (COMPLETE↔SUCCESS, PARTIALLY_COMPLETE↔PARTIAL, NOT_STARTED↔FAILED); (b) the record appears in the request's own snapshot; (c) one record of each kind per request; (d) policy actions run as a roughly 7-minute chain per request. | 100% | 0.982 |
| v5 | **Proof-aware refinement.** A COMPLETE request must be provable, so an ambiguous profile that was read back goes to the request that needs it as proof. Unproven ambiguous records move to incomplete candidates. | 100% | 0.987 |
| v6 | **Robustness from custom cases.** C3 showed that an inventory captured for other requests was "proving" a data flow disabled because its row was missing. Absence-by-omission is now limited to delete-type systems and to the request's own snapshot. | 100% | 0.987 |
| v7 | **Explainability.** Added per-case evidence trail, confidence grading, `explain.py`, and the ablation study. Tie-break cascades are now flagged: case_23 had been reported "deduced" although its competitor was placed by tie-break. The emitted `output.csv` is byte-identical. | 100% | 0.987 |

Other fixes found while reviewing full-dataset output:

- An unhandled log event (`retained_order_loaded`) dropped legal-hold records.
- Data-catalog links were wrongly rejected when a record carried only a non-identifying field such as `uploaded_by: support-service`.
- Rows mentioned only in passing in screenshots (for example five other audit events in a security explorer) are now marked context-only, so they aren't attributed to the requester.

## Known limitations and judgment calls

- **case_63:** the only evidence for the requester is a catalog link that the record itself contradicts. Nothing attributable remains, so the agent returns COMPLETE with no steps instead of inventing a verification.
- **Remaining ties:** about 2–3% of identifier-free records end in a true tie between requests with the same `reported_at` and claimed status. They're broken deterministically (nearest time, then case id).
- **Activity rows as fallback:** these are used only when no evidence file covers a resource (for example "Connector status check confirmed … remains enabled"). The cited id is then the `activity_id`.
