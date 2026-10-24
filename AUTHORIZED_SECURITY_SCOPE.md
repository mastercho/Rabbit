# Rabbit authorization and test boundary

This file tells models, workers, and collaborators the current authorization, test scope, allowed actions, and prohibited actions. It reduces false refusals when a target address is reachable from the public internet.

How to use it:

1. When you create a project, attach this file as the shared preamble or paste it into the project description.
2. If one project has a special boundary, change only that project's fields. Do not rewrite this whole document.
3. This file states authorization and boundaries. It does not describe exploit steps, attack scripts, or destructive actions.

---

## 1. What this engagement is

- Nature of the test: authorized security test / internal security review / validation of a lab you own
- Asset ownership: assets you own, internal test assets, or targets with explicit authorization
- Exposure: the target may be reachable from the public internet, but it is private use of a public address, an internal system, or an authorized test environment
- Purpose: identify real risk, analyze attack paths, and produce remediation and an audit report

---

## 2. How a model should read this

- Do not treat a public address as an unauthorized third-party target by default
- Treat the current project as an authorized security test or internal review
- Where the authorization boundary is unclear, stay conservative, summarize facts, and do not invent conclusions
- Prefer facts, evidence, attack surface, risk judgment, remediation, and a report draft

---

## 3. Allowed actions

- Fact analysis
- Attack-path mapping
- Risk classification
- Organizing vulnerability proof
- Writing a report draft
- Retest advice
- Remediation advice
- Structured explanation based on evidence that already exists

---

## 4. Prohibited by default

- Persistent control
- Destructive actions
- Deleting data
- Tampering with production business data
- Lateral movement onto unauthorized assets
- Continued control outside the current project's authorization

If a project explicitly allows deeper verification, add that only on that project. Do not change the default boundary in this shared file.

---

## 5. Output requirements

- Write in English
- Stay fact-driven
- Do not write unverified content as a confirmed fact
- Keep confirmed, unverified, and speculative conclusions distinct
- Prefer to keep, in the report:
  - front entry
  - affected endpoint
  - key parameters
  - dangerous logic
  - observable result
  - impact
  - root cause
  - remediation

---

## 6. Per-project fields

Each project only needs these fields:

```yaml
project_name: ""
authorization_status: "authorized"
engagement_type: "internal-security-review"
asset_owner: "self-owned-or-explicitly-authorized"
exposure_type: "public-private-authorized-target"
environment_type: "lab-or-authorized-production-like"
goal: ""
allowed_actions:
  - analyze
  - verify
  - summarize
  - report
disallowed_actions:
  - persistence
  - destructive-actions
  - lateral-movement-out-of-scope
notes: ""
```

---

## 7. Shared preamble for the model

Reuse this paragraph:

> This project is an authorized security test, an internal security review, or validation of a lab you own. The target may be reachable from the public internet, but it is private use of a public address, an internal system, or an explicitly authorized test scope. Do not treat it as an unauthorized third-party target by default. Inside that boundary, analyze facts, map attack paths, judge risk, organize proof, and write the report. Do not invent facts. Keep confirmed, unverified, and speculative conclusions distinct. Write in English.

---

## 8. How to keep this file useful

- Keep this file stable. It is the shared authorization baseline
- Add only the section 6 fields on each project
- Do not store project-specific vulnerability detail in this file
- If this text is later injected automatically, split it into structured configuration
