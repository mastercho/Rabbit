"""Read-only vulnerability report composition service.

This service turns an already-confirmed merged vulnerability into a clearer,
delivery-oriented report draft. It uses a deterministic template by default and
can optionally ask a dedicated language model to polish the narrative while
remaining grounded in the same source evidence.

Important constraints:

* No new persistence is introduced.
* The core dispatcher / project execution flow is untouched.
* The model is never asked to invent facts or generate executable exploit
  scripts, payloads, or weaponized step-by-step instructions.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import requests
import yaml

from cairn.server.db import get_conn
from cairn.server.report_composer_models import (
    VulnerabilityNarrativeReport,
    VulnerabilityProofPoint,
)
from cairn.server.vulnerabilities_models import Vulnerability

LOG = logging.getLogger(__name__)

_REPORT_TIMEOUT_SECONDS = 300
_TRAILING_PUNCTUATION = "`'\"*()[]{}<>，。；;：:,."
_CONFIG_PATH_ENV = "CAIRN_REPORT_COMPOSER_CONFIG_PATH"

# Local filesystem locations are workspace artifacts (exploit scripts, tool
# caches), never attack-surface endpoints.  Mirrors the prefix list used by the
# endpoint extractor in the vulnerabilities router.
_FILESYSTEM_PREFIXES = (
    "/bin/", "/dev/", "/etc/", "/home/", "/opt/",
    "/proc/", "/root/", "/tmp/", "/usr/", "/var/",
)

# Loopback addresses appear constantly in worker-side verification text; a
# client-facing report should prefer the externally reachable target.
_LOCAL_HOSTNAMES = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


def _json_object(raw: str | None) -> dict[str, Any]:
    try:
        value = json.loads(raw or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


@dataclass(frozen=True)
class _ComposerProfile:
    model: str
    base_url: str
    api_key: str
    provider_api: str = "openai-completions"


@dataclass(frozen=True)
class _ReportContext:
    origin: str
    goal: str
    related_facts: list[tuple[str, str]]
    source_intent_description: str | None


def compose_vulnerability_report(
    vulnerability: Vulnerability,
    *,
    use_model: bool = False,
) -> VulnerabilityNarrativeReport:
    """Compose a delivery-grade report draft for one merged vulnerability."""
    context = _load_report_context(vulnerability)
    fallback = _build_template_report(vulnerability, context)
    if not use_model:
        return fallback

    profile = _resolve_report_composer_profile()
    if profile is None:
        return fallback

    enhanced = _compose_with_model(vulnerability, context, fallback, profile)
    return enhanced or fallback


def render_narrative_markdown(report: VulnerabilityNarrativeReport) -> list[str]:
    """Render one composed vulnerability report as Markdown lines."""
    lines = [
        "#### Summary",
        "",
        report.executive_summary,
        "",
    ]

    if report.attack_surface:
        lines.extend(["#### Attack surface", ""])
        for item in report.attack_surface:
            lines.append(f"- {item}")
        lines.append("")

    lines.extend(["#### Proof", "", report.vulnerability_proof, ""])

    if report.proof_points:
        lines.extend(["##### Proof points", ""])
        for point in report.proof_points:
            lines.append(f"- **{point.label}**: {point.content}")
        lines.append("")

    lines.extend(
        [
            "#### Impact",
            "",
            report.impact,
            "",
            "#### Root cause",
            "",
            report.root_cause,
            "",
        ]
    )

    if report.evidence_highlights:
        lines.extend(["#### Key evidence", ""])
        for item in report.evidence_highlights:
            lines.append(f"- {item}")
        lines.append("")

    if report.remediation:
        lines.extend(["#### Remediation", ""])
        for item in report.remediation:
            lines.append(f"- {item}")
        lines.append("")

    if report.operator_notes:
        lines.extend(["#### Notes", ""])
        for item in report.operator_notes:
            lines.append(f"- {item}")
        lines.append("")

    return lines


def render_narrative_plain_lines(report: VulnerabilityNarrativeReport) -> list[str]:
    """Render one composed vulnerability report as wrapped plain-text lines."""
    lines = [
        "Summary:",
        report.executive_summary,
        "",
    ]
    if report.attack_surface:
        lines.append("Attack surface:")
        for item in report.attack_surface:
            lines.append(f"- {item}")
        lines.append("")

    lines.extend(["Proof:", report.vulnerability_proof, ""])
    if report.proof_points:
        lines.append("Proof points:")
        for point in report.proof_points:
            lines.append(f"- {point.label}: {point.content}")
        lines.append("")

    lines.extend(["Impact:", report.impact, "", "Root cause:", report.root_cause, ""])
    if report.evidence_highlights:
        lines.append("Key evidence:")
        for item in report.evidence_highlights:
            lines.append(f"- {item}")
        lines.append("")
    if report.remediation:
        lines.append("Remediation:")
        for item in report.remediation:
            lines.append(f"- {item}")
        lines.append("")
    if report.operator_notes:
        lines.append("Notes:")
        for item in report.operator_notes:
            lines.append(f"- {item}")
    return lines


def _load_finding_enrichment(vulnerability: Vulnerability) -> dict[str, Any]:
    """Stored report-agent enrichment for the finding behind this projection.

    The background agent already produced a grounded location/impact/
    remediation from the confirmed evidence.  The deterministic template
    prefers that material over re-extracting from raw text; regex extraction
    stays as the fallback for findings the agent has not enriched yet.
    """
    if not vulnerability.finding_id:
        return {}
    with get_conn() as conn:
        row = conn.execute(
            "SELECT data_json FROM findings WHERE project_id = ? AND id = ?",
            (vulnerability.project_id, vulnerability.finding_id),
        ).fetchone()
    if row is None:
        return {}
    enrichment = _json_object(row["data_json"]).get("report_enrichment")
    return enrichment if isinstance(enrichment, dict) else {}


def _build_template_report(
    vulnerability: Vulnerability,
    context: _ReportContext,
) -> VulnerabilityNarrativeReport:
    enrichment = _load_finding_enrichment(vulnerability)
    location_hint = str(enrichment.get("location") or "").strip() or None
    full_text = _full_text(vulnerability, context)
    vuln_type = _classify_vulnerability(full_text)
    front_entry, backend_entry = _entry_points(
        full_text, vulnerability.proof_packets or [], location_hint=location_hint
    )
    param_names = _parameter_names(full_text, vulnerability.proof_packets or [])
    observed = _observed_result(vulnerability, context)
    root_cause = _root_cause(vuln_type, full_text)
    impact = (
        str(enrichment.get("impact") or "").strip()
        or _impact_statement(vuln_type, vulnerability, observed)
    )
    proof_points = _proof_points(
        front_entry=front_entry,
        backend_entry=backend_entry,
        param_names=param_names,
        root_cause=root_cause,
        observed=observed,
        impact=impact,
    )
    enrichment_proof = str(enrichment.get("proof") or "").strip()
    if enrichment_proof:
        proof_points.insert(
            0, VulnerabilityProofPoint(label="Evidence", content=_first_line(enrichment_proof, 220))
        )
    for point in _verification_evidence(vulnerability, context, observed):
        if not any(existing.label == point.label and existing.content == point.content for existing in proof_points):
            proof_points.append(point)
    attack_surface = _attack_surface(front_entry, backend_entry, param_names, context.origin)
    if location_hint:
        attack_surface.insert(0, f"Location: {_first_line(location_hint, 160)}")
    evidence_highlights = _evidence_highlights(vulnerability, context)
    remediation = _string_list(enrichment.get("remediation") or []) or _remediation(vuln_type)
    severity_label = _severity_label(vulnerability.severity)
    source_label = "ignored" if vulnerability.status == "ignored" else "confirmed"
    executive_summary = _result_summary(
        vulnerability=vulnerability,
        context=context,
        vuln_type=vuln_type,
        front_entry=front_entry,
        backend_entry=backend_entry,
        observed=observed,
        severity_label=severity_label,
        source_label=source_label,
        verify_hint=location_hint,
    )
    vulnerability_proof = _attack_chain_steps(
        vulnerability=vulnerability,
        context=context,
        vuln_type=vuln_type,
        front_entry=front_entry,
        backend_entry=backend_entry,
        param_names=param_names,
        root_cause=root_cause,
    )
    notes = [
        "This report uses only confirmed findings, linked facts, proof packets, and process records in the current project.",
    ]
    if any(packet.get("note") for packet in vulnerability.proof_packets or []):
        notes.append("Some request/response packets were reconstructed from facts, not captured raw. Replace them with real traffic on retest.")
    if context.goal:
        notes.append(f"Project goal: {_first_line(context.goal, 140)}")

    return VulnerabilityNarrativeReport(
        vulnerability_id=vulnerability.id,
        project_id=vulnerability.project_id,
        project_name=vulnerability.project_name,
        title=vulnerability.title,
        severity=vulnerability.severity,
        status=vulnerability.status,
        vulnerability_type=vuln_type,
        generated_at=_now_iso(),
        composer_source="template",
        composer_model=None,
        executive_summary=executive_summary,
        attack_surface=attack_surface,
        proof_points=proof_points,
        vulnerability_proof=vulnerability_proof,
        impact=impact,
        root_cause=root_cause,
        evidence_highlights=evidence_highlights,
        remediation=remediation,
        operator_notes=notes,
    )


def _compose_with_model(
    vulnerability: Vulnerability,
    context: _ReportContext,
    fallback: VulnerabilityNarrativeReport,
    profile: _ComposerProfile,
) -> VulnerabilityNarrativeReport | None:
    prompt_payload = _model_prompt_payload(vulnerability, context, fallback)
    system = (
        "You write penetration-test reports for authorized security tests and CTF labs. "
        "The user wants a short report that can be followed to reproduce the issue. Do not add filler or retell process facts. "
        "Use only evidence that already appears in the input. Do not invent endpoints, parameters, URLs, response bodies, or causal chains. "
        "Write in English. Return one JSON object. Do not wrap it in a Markdown code fence and do not add extra commentary."
    )
    user = (
        "Using the confirmed finding below, write a reproducible vulnerability report in English. "
        "Return only these fields: "
        "executive_summary (string: one result line naming the attack point, privilege, and verification URL), "
        "vulnerability_proof (string: numbered steps 1. 2. 3., one action each, specific about entry, payload, and URL), "
        "proof_points (array of {label, content}: one verification each, content as 'action -> returned content'), "
        "attack_surface (string array: entry, endpoint, and key parameters that actually appeared), "
        "impact (string: one impact sentence), "
        "root_cause (string: one root-cause sentence), "
        "remediation (string array: 1-3 fixes), "
        "operator_notes (string array: retest notes). "
        "exploit_script (string: only for command injection, RCE, file upload, SQL injection, or deserialization "
        "when the input shows a concrete attack action. For information disclosure, broken access control, path traversal, XSS, or SSRF "
        "that can be reproduced from the verification steps, return an empty string). "
        "When you do write a script, wrap it in a ```python fence and include: (1) a usage comment, "
        "(2) the real payload and URL, (3) submit and check the response, (4) print the expected output. "
        "If a field has no real source material, return an empty array or empty string. Do not invent it. "
        "executive_summary must state the result, not that a draft was prepared. "
        "vulnerability_proof must say which entry was opened, what payload was built, where it was submitted, and which URL verified it."
        "\n\nContext:\n"
        + json.dumps(prompt_payload, ensure_ascii=False, separators=(",", ":"))
    )
    # Single attempt: glm-5.x reasoning is slow (~200s for full reports),
    # and a second attempt would double the wait. On failure, fall back to
    # the template (which is itself a usable reproducible report).
    for _attempt in range(1):
        content = _request_model_json(system=system, user=user, profile=profile)
        if content is None:
            continue
        payload = _extract_json_payload(content)
        if not isinstance(payload, dict):
            continue

        merged = fallback.model_dump(mode="json")
        merged["composer_source"] = "model"
        merged["composer_model"] = profile.model
        merged["generated_at"] = _now_iso()
        for field in (
            "executive_summary",
            "vulnerability_proof",
            "impact",
            "root_cause",
            "exploit_script",
        ):
            value = payload.get(field)
            if isinstance(value, str) and value.strip():
                merged[field] = value.strip()
        for field in ("attack_surface", "evidence_highlights", "remediation", "operator_notes"):
            value = payload.get(field)
            if isinstance(value, list):
                merged[field] = _string_list(value)
        proof_points = payload.get("proof_points")
        if isinstance(proof_points, list):
            normalized_points: list[dict[str, str]] = []
            for item in proof_points:
                if not isinstance(item, dict):
                    continue
                label = str(item.get("label") or "").strip()
                content_value = str(item.get("content") or "").strip()
                if not label or not content_value:
                    continue
                normalized_points.append({"label": label, "content": content_value})
            if normalized_points:
                merged["proof_points"] = normalized_points
        try:
            return VulnerabilityNarrativeReport.model_validate(merged)
        except Exception:
            continue
    LOG.warning(
        "Report model enhancement failed; using the template. vulnerability=%s project=%s", vulnerability.id, vulnerability.project_id
    )
    return None


def _request_model_json(
    *,
    system: str,
    user: str,
    profile: _ComposerProfile,
    raise_errors: bool = False,
) -> str | None:
    if profile.provider_api != "openai-completions":
        if raise_errors:
            raise RuntimeError(f"Report agent does not support provider API {profile.provider_api}")
        return None
    endpoint = profile.base_url.rstrip("/")
    if not endpoint.endswith("/chat/completions"):
        endpoint = endpoint + "/chat/completions"
    payload = {
        "model": profile.model,
        "temperature": 0.15,
        # glm-5.x spends most of its budget on reasoning_content (chain of
        # thought) before emitting the final JSON in content. With a small
        # max_tokens the reasoning eats everything and content comes back
        # empty, which previously made use_model=True silently fall back to
        # the template. 6000 leaves enough room for reasoning + a full JSON
        # report. Slow but necessary for this model family.
        "max_tokens": 6000,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    try:
        response = requests.post(
            endpoint,
            headers={
                "Authorization": f"Bearer {profile.api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=_REPORT_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except requests.HTTPError as exc:
        if raise_errors:
            status = exc.response.status_code if exc.response is not None else "unknown"
            raise RuntimeError(f"Report agent API returned HTTP {status}") from exc
        return None
    except requests.RequestException as exc:
        if raise_errors:
            raise RuntimeError(f"Report agent connection failed: {exc.__class__.__name__}") from exc
        return None
    except Exception as exc:
        if raise_errors:
            raise RuntimeError(f"Report agent call failed: {exc.__class__.__name__}") from exc
        return None

    try:
        body = response.json()
    except ValueError as exc:
        if raise_errors:
            raise RuntimeError("Report agent API did not return valid JSON") from exc
        return None

    # Parse the OpenAI-style chat completion response. This previously lived
    # as dead code after _model_prompt_payload's return statement (a paste
    # error), which made _request_model_json always return None and silently
    # broke the use_model=True LLM report path.
    try:
        choices = body.get("choices") or []
        message = choices[0].get("message") or {}
        content = message.get("content")
    except Exception as exc:
        if raise_errors:
            raise RuntimeError("Report agent response has no choices/message structure") from exc
        return None

    if isinstance(content, str):
        result = content.strip() or None
        if result is None and raise_errors:
            raise RuntimeError("Report agent returned empty content")
        return result
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        text = "\n".join(parts).strip()
        if not text and raise_errors:
            raise RuntimeError("Report agent returned empty content")
        return text or None
    if raise_errors:
        raise RuntimeError("Report agent returned an unsupported content format")
    return None


def _model_prompt_payload(
    vulnerability: Vulnerability,
    context: _ReportContext,
    fallback: VulnerabilityNarrativeReport,
) -> dict[str, Any]:
    return {
        "report_target": {
            "id": vulnerability.id,
            "project_id": vulnerability.project_id,
            "project_name": vulnerability.project_name,
            "title": vulnerability.title,
            "severity": vulnerability.severity,
            "status": vulnerability.status,
            "fact_id": vulnerability.fact_id,
            "vulnerability_type": fallback.vulnerability_type,
        },
        "grounding": {
            "description": _trim(vulnerability.description, 400),
            "source_intent_id": vulnerability.source_intent_id,
            "source_intent_description": _trim(
                vulnerability.source_intent_description or "",
                140,
            ),
            "source_worker": vulnerability.source_worker,
            "evidence_highlights": _evidence_highlights(vulnerability, context)[:3],
            "process_highlights": [
                {
                    "label": str(step.get("label") or step.get("type") or step.get("id") or "step"),
                    "worker": str(step.get("worker") or "").strip() or None,
                    "description": _trim(str(step.get("description") or ""), 120),
                }
                for step in (vulnerability.process or [])[:3]
                if str(step.get("description") or "").strip()
            ],
            "proof_packets": [
                {
                    "title": _trim(str(packet.get("title") or f"Proof {index + 1}"), 80),
                    "request_target": _trim(_request_target(packet), 140),
                    "response": _trim(_first_line(str(packet.get("response") or ""), 160), 160),
                    "note": _trim(str(packet.get("note") or ""), 100),
                }
                for index, packet in enumerate((vulnerability.proof_packets or [])[:2])
            ],
        },
        "project_context": {
            "origin": _trim(context.origin, 120),
            "goal": _trim(context.goal, 120),
            "related_facts": [
                {"id": fact_id, "description": _trim(description, 140)}
                for fact_id, description in context.related_facts[:3]
            ],
            "source_intent_description": _trim(context.source_intent_description or "", 140),
        },
    }


def _resolve_report_composer_profile() -> _ComposerProfile | None:
    explicit_model = os.environ.get("CAIRN_REPORT_COMPOSER_MODEL", "").strip()
    explicit_base = os.environ.get("CAIRN_REPORT_COMPOSER_BASE_URL", "").strip()
    explicit_key = os.environ.get("CAIRN_REPORT_COMPOSER_API_KEY", "").strip()
    explicit_provider = os.environ.get("CAIRN_REPORT_COMPOSER_PROVIDER_API", "").strip() or "openai-completions"
    if explicit_model and explicit_base and explicit_key:
        return _ComposerProfile(
            model=explicit_model,
            base_url=explicit_base,
            api_key=explicit_key,
            provider_api=explicit_provider,
        )

    for path in _candidate_config_paths():
        if not path.exists():
            continue
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        workers = payload.get("workers")
        if not isinstance(workers, list):
            continue
        candidates: list[tuple[int, _ComposerProfile]] = []
        for item in workers:
            if not isinstance(item, dict):
                continue
            if item.get("type") != "pi" or item.get("enabled") is False:
                continue
            env = item.get("env") or {}
            if not isinstance(env, dict):
                continue
            model = str(env.get("PI_MODEL") or "").strip()
            base_url = str(env.get("PI_BASE_URL") or "").strip()
            # dispatch.yaml stores the key as ${PI_API_KEY_GLM}; expand it
            # against the server process env (populated via docker env_file:
            # .env). Without this the LLM call goes out with a literal
            # "${PI_API_KEY_GLM}" key and 401s back to template.
            api_key = os.path.expandvars(str(env.get("PI_API_KEY") or "")).strip()
            provider_api = str(env.get("PI_PROVIDER_API") or "openai-completions").strip()
            if not model or not base_url or not api_key:
                continue
            score = 0
            lowered = model.lower()
            if lowered == "gpt-5.4":
                score += 100
            if "5.4" in lowered:
                score += 40
            if "chat5.5" in str(item.get("name") or "").lower():
                score += 15
            score -= int(item.get("priority") or 0)
            candidates.append(
                (
                    score,
                    _ComposerProfile(
                        model=model,
                        base_url=base_url,
                        api_key=api_key,
                        provider_api=provider_api or "openai-completions",
                    ),
                )
            )
        if candidates:
            candidates.sort(key=lambda pair: pair[0], reverse=True)
            return candidates[0][1]
    return None


def _candidate_config_paths() -> list[Path]:
    paths: list[Path] = []
    raw = os.environ.get(_CONFIG_PATH_ENV, "").strip()
    if raw:
        paths.append(Path(raw))
    paths.append(Path("/cairn/dispatch.yaml"))
    current = Path(__file__).resolve()
    for parent in current.parents:
        candidate = parent / "dispatch.yaml"
        if candidate not in paths:
            paths.append(candidate)
    return paths


def _load_report_context(vulnerability: Vulnerability) -> _ReportContext:
    with get_conn() as conn:
        fact_rows = conn.execute(
            "SELECT id, description FROM facts WHERE project_id = ? ORDER BY rowid",
            (vulnerability.project_id,),
        ).fetchall()
        step_description = vulnerability.source_intent_description
        if not step_description and vulnerability.source_intent_id:
            step_row = conn.execute(
                "SELECT description FROM steps WHERE project_id = ? AND id = ?",
                (vulnerability.project_id, vulnerability.source_intent_id),
            ).fetchone()
            if step_row:
                step_description = str(step_row["description"] or "").strip()

    fact_by_id = {str(row["id"]): str(row["description"] or "").strip() for row in fact_rows}
    related_ids = _unique(
        [
            vulnerability.fact_id,
            *(vulnerability.related_fact_ids or []),
            *(vulnerability.source_fact_ids or []),
        ]
    )
    related_facts = [(fact_id, fact_by_id[fact_id]) for fact_id in related_ids if fact_id in fact_by_id]
    return _ReportContext(
        origin=fact_by_id.get("origin", ""),
        goal=fact_by_id.get("goal", ""),
        related_facts=related_facts,
        source_intent_description=step_description,
    )


def _full_text(vulnerability: Vulnerability, context: _ReportContext) -> str:
    parts = [
        vulnerability.title,
        vulnerability.description,
        context.origin,
        context.goal,
        context.source_intent_description or "",
        *(description for _fact_id, description in context.related_facts),
        *(vulnerability.evidence or []),
        *[
            " ".join(str(step.get(key) or "") for key in ("label", "type", "id", "description", "worker"))
            for step in (vulnerability.process or [])
        ],
        *[
            " ".join(
                str(packet.get(key) or "")
                for key in ("title", "request", "response", "note")
            )
            for packet in (vulnerability.proof_packets or [])
        ],
    ]
    return "\n".join(part for part in parts if part).strip()


def _classify_vulnerability(text: str) -> str:
    rules = (
        ("Command injection", (r"命令注入", r"command injection", r"shell=true", r"subprocess", r"randomstring")),
        ("SQL injection", (r"sql 注入", r"sql injection", r"\bsqli\b")),
        ("Deserialization", (r"反序列化", r"deseriali[sz]ation", r"\bphar\b", r"\bserialize\b")),
        ("File upload", (r"文件上传", r"upload", r"\.phar\b", r"multipart/form-data")),
        ("Path traversal", (r"路径穿越", r"path traversal", r"directory traversal", r"任意文件读取", r"\.\./")),
        ("Broken access control", (r"未授权", r"越权", r"idor", r"authentication bypass", r"鉴权缺失")),
        ("SSRF", (r"\bssrf\b", r"server-side request forgery")),
        ("XXE", (r"\bxxe\b", r"xml external entity")),
        ("Cross-site scripting", (r"\bxss\b", r"跨站脚本", r"script 注入")),
        ("Information disclosure", (r"信息泄露", r"information disclosure", r"泄露", r"直接返回")),
        ("Remote code execution", (r"\brce\b", r"远程代码执行", r"远程命令执行")),
    )
    lowered = text.lower()
    for label, patterns in rules:
        if any(re.search(pattern, lowered, re.IGNORECASE) for pattern in patterns):
            return label
    return "General security weakness"


def _entry_points(
    text: str,
    proof_packets: list[dict[str, str]],
    location_hint: str | None = None,
) -> tuple[str | None, str | None]:
    paths = _extract_paths(text)
    # Enrichment location (when present) is grounded evidence; its endpoints
    # come ahead of anything re-extracted from raw text.
    hint_paths = _extract_paths(location_hint) if location_hint else []
    packet_targets = [_request_target(packet) for packet in proof_packets]
    combined = _unique([*packet_targets, *hint_paths, *paths])
    if not combined:
        return None, None

    front_entry = next(
        (
            item
            for item in combined
            if item.endswith("/")
            and not any(token in item.lower() for token in ("cgi-bin", "/api/", ".php", ".jsp", ".py"))
        ),
        None,
    )
    backend_entry = next(
        (
            item
            for item in combined
            if any(token in item.lower() for token in ("cgi-bin", "/api/", ".php", ".jsp", ".py", ".action"))
        ),
        None,
    )
    if front_entry is None and combined:
        front_entry = combined[0]
    if backend_entry is None:
        backend_entry = combined[0] if combined else None
    return front_entry, backend_entry


def _attack_surface(
    front_entry: str | None,
    backend_entry: str | None,
    param_names: list[str],
    origin: str,
) -> list[str]:
    items: list[str] = []
    if front_entry:
        items.append(f"Entry: {front_entry}")
    if backend_entry:
        items.append(f"Endpoint: {backend_entry}")
    if param_names:
        items.append(f"Key parameters: {', '.join(param_names[:6])}")
    if origin:
        items.append(f"Origin: {_first_line(origin, 160)}")
    return _unique(items)


def _result_summary(
    *,
    vulnerability: Vulnerability,
    context: _ReportContext,
    vuln_type: str,
    front_entry: str | None,
    backend_entry: str | None,
    observed: str,
    severity_label: str,
    source_label: str,
    verify_hint: str | None = None,
) -> str:
    """结果段: RCE 点 + 权限 + 验证 URL. 复现入口, 不写套话."""
    # 1. 攻击点: 优先用 backend_entry (命中接口), 否则 front_entry
    attack_point = backend_entry or front_entry or vulnerability.title
    # 2. 权限: 从 observed / fact 文本里抓 uid=/www-data/root
    text = f"{vulnerability.description}\n{observed}\n" + "\n".join(
        d for _id, d in context.related_facts
    ) + "\n" + "\n".join(vulnerability.evidence or [])
    perm = "not identified"
    m = re.search(r"uid=\d+\((?:root|www-data|daemon|nobody)\)", text)
    if m:
        perm = m.group(0)
    elif re.search(r"\bwhoami\b", text, re.IGNORECASE) and re.search(r"\b(?:root|www-data)\b", text, re.IGNORECASE):
        perm = "www-data / root"
    # 3. 验证 URL: 优先增强 location 中的入口，其次从 fact 里找带成功信号的 URL
    verify_url = ""
    verify_candidates: list[str] = []
    if verify_hint:
        for url_m in re.finditer(r"https?://[^\s,；,)）<>{}]+", verify_hint):
            verify_candidates.append(url_m.group(0).rstrip(".;"))
    for url_m in re.finditer(r"https?://[^\s,；,)）<>{}]+", text):
        url = url_m.group(0).rstrip(".;")
        # 找这个 URL 附近有没有"200 / 返回 / uid= / www-data"
        after = text[url_m.end():url_m.end() + 120]
        if re.search(r"200|返回|uid=|www-data|ifconfig|成功", after, re.IGNORECASE):
            verify_candidates.append(url)
    if verify_candidates:
        # Loopback URLs come from worker-side local verification; prefer the
        # externally reachable target when one is available.
        verify_url = next(
            (u for u in verify_candidates if urlsplit(u).hostname not in _LOCAL_HOSTNAMES),
            verify_candidates[0],
        )
    bits = [
        f"Attack point: {attack_point}",
        f"Severity: {severity_label} ({vuln_type})",
        f"Privilege: {perm}",
    ]
    if verify_url:
        bits.append(f"Verification URL: {verify_url}")
    bits.append(f"Status: {source_label}")
    return " | ".join(bits)


def _attack_chain_steps(
    *,
    vulnerability: Vulnerability,
    context: _ReportContext,
    vuln_type: str,
    front_entry: str | None,
    backend_entry: str | None,
    param_names: list[str],
    root_cause: str,
) -> str:
    """漏洞链段: 从 fact 文本提取动作序列, 输出 1234 步骤.
    优先抓 payload (含 ; > | $ 等元字符的文件名/参数值) 和上传/访问动作."""
    text = _full_text(vulnerability, context)
    steps: list[str] = []
    # 步骤1: 入口
    entry = backend_entry or front_entry
    if entry:
        steps.append(f"Open {entry}")
    if param_names:
        steps.append(f"Key parameters: {', '.join(param_names[:6])}")
    # 步骤2: 从 fact 里抓 payload (文件名/参数值含 shell 元字符)
    payloads = re.findall(
        r"[`'\"]?([A-Za-z0-9_./-]*[;|>`$][^'\"\s,；,)）]{0,80})[`'\"]?",
        text,
    )
    # 过滤掉太短或明显是路径的
    payloads = [
        p
        for p in payloads
        if len(p) > 6
        and any(marker in p for marker in (";", ">", "$(", "|"))
        # "8088->容器8090" style port-mapping notes are not payloads.
        and not re.match(r"^\d[\d.]*->", p)
    ][:3]
    seen_p = set()
    for p in payloads:
        p_clean = p.strip("'\"`")
        if p_clean and p_clean not in seen_p:
            seen_p.add(p_clean)
            steps.append(f"Build payload: {p_clean}")
    # 步骤3: 上传/提交动作
    if re.search(r"POST|上传|提交|multipart", text, re.IGNORECASE):
        steps.append(f"POST to {entry or 'the target endpoint'}")
    # 步骤4: 验证
    verify_urls = []
    for url_m in re.finditer(r"https?://[^\s,；,)）]+(?:\.txt|\.php|/output/[^\s,；,)）]+)", text):
        url = url_m.group(0).rstrip(".;")
        after = text[url_m.end():url_m.end() + 100]
        if re.search(r"200|返回|uid=|www-data|ifconfig|成功|PWNED", after, re.IGNORECASE):
            if url not in verify_urls:
                verify_urls.append(url)
    for url in verify_urls[:2]:
        steps.append(f"GET {url} and check the response")
    if not steps:
        # fallback: 至少给出 root_cause
        steps.append(root_cause)
    # 编号
    return "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps))


def _verification_evidence(
    vulnerability: Vulnerability,
    context: _ReportContext,
    observed: str,
) -> list[VulnerabilityProofPoint]:
    """验证证据段: 每条 = 一个验证动作 + 实际返回内容.
    从 proof_packets 的 response + fact 里的成功信号提取."""
    points: list[VulnerabilityProofPoint] = []
    # 1. 从 proof_packets 的 response 里找成功证据
    for packet in (vulnerability.proof_packets or [])[:3]:
        response = str(packet.get("response") or "").strip()
        if not response:
            continue
        # 找带成功信号的 response
        if re.search(r"uid=|www-data|root|PWNED|ifconfig|200|成功|返回", response, re.IGNORECASE):
            title = packet.get("title") or "Verification"
            # 响应内容取首行 + 关键片段
            head = response.split("\n")[0][:160]
            points.append(VulnerabilityProofPoint(label=title, content=head))
    # 2. 从 fact 里找"URL 返回 xxx"的成功验证
    text = _full_text(vulnerability, context)
    for m in re.finditer(
        r"(https?://[^\s,；,)）]+).{0,80}?(返回\s*200|uid=\d+\([^)]+\)|www-data|ifconfig|PWNED|成功)",
        text,
        re.IGNORECASE,
    ):
        url = m.group(1).rstrip(".;")
        signal = m.group(2)
        if not any(url in p.content for p in points):
            points.append(VulnerabilityProofPoint(label="HTTP verification", content=f"{url} → {signal}"))
        if len(points) >= 4:
            break
    # 3. 兜底: 用 observed
    if not points and observed:
        points.append(VulnerabilityProofPoint(label="Observed result", content=observed))
    return points


def _proof_points(
    *,
    front_entry: str | None,
    backend_entry: str | None,
    param_names: list[str],
    root_cause: str,
    observed: str,
    impact: str,
) -> list[VulnerabilityProofPoint]:
    points: list[VulnerabilityProofPoint] = []
    if front_entry:
        points.append(VulnerabilityProofPoint(label="Entry", content=front_entry))
    if backend_entry:
        points.append(VulnerabilityProofPoint(label="Endpoint", content=backend_entry))
    if param_names:
        points.append(VulnerabilityProofPoint(label="Key parameters", content=", ".join(param_names[:6])))
    points.append(VulnerabilityProofPoint(label="Dangerous logic", content=root_cause))
    points.append(VulnerabilityProofPoint(label="Observed result", content=observed))
    points.append(VulnerabilityProofPoint(label="Impact", content=impact))
    return points


def _proof_paragraph(
    *,
    vuln_type: str,
    front_entry: str | None,
    backend_entry: str | None,
    param_names: list[str],
    root_cause: str,
    observed: str,
    impact: str,
) -> str:
    route_bits = []
    if front_entry:
        route_bits.append(f"the entry is {front_entry}")
    if backend_entry and backend_entry != front_entry:
        route_bits.append(f"the handling point is {backend_entry}")
    param_text = f"key input is {', '.join(param_names[:6])}" if param_names else "the material does not fully record parameter names"
    return (
        f"The main proof chain for this {vuln_type} report is: "
        f"{', '.join(route_bits) if route_bits else 'a reachable entry is confirmed'}, {param_text}. "
        f"Recorded evidence shows that {root_cause}, so the system produced this observable result: \"{observed}\". "
        f"That supports this impact: \"{impact}\"."
    )


def _root_cause(vuln_type: str, text: str) -> str:
    if vuln_type == "Command injection":
        if re.search(r"shell\s*=\s*true|subprocess", text, re.IGNORECASE):
            return "The server concatenates attacker-controlled input into a shell command without isolating the command boundary"
        return "The server passes external input into a command execution path without strict parameter isolation or an allowlist"
    if vuln_type == "SQL injection":
        return "The server builds a database query from external input without parameterization or an equivalent binding"
    if vuln_type == "Deserialization":
        return "The server deserializes untrusted data without restricting object types or origin"
    if vuln_type == "File upload":
        return "Upload type, parsing scope, or storage location checks are too weak, so an unsafe file reaches later processing"
    if vuln_type == "Path traversal":
        return "Path normalization or directory boundaries are insufficient, so external input can leave the intended directory"
    if vuln_type == "Broken access control":
        return "The endpoint lacks effective authentication or object-level authorization, so an unauthorized caller can reach the resource"
    if vuln_type == "SSRF":
        return "The server sends outbound requests without restricting target, protocol, or address range"
    if vuln_type == "XXE":
        return "The XML parser allows external entities and the input source is not restricted"
    if vuln_type == "Cross-site scripting":
        return "Output of controllable content is missing context-specific encoding and filtering"
    if vuln_type == "Information disclosure":
        return "A sensitive resource or internal state is exposed on an accessible endpoint without least-exposure controls"
    if vuln_type == "Remote code execution":
        return "A server execution path does not constrain controllable input and can run code or commands"
    return "A critical processing path does not constrain external input, so a security boundary is crossed"


def _impact_statement(
    vuln_type: str,
    vulnerability: Vulnerability,
    observed: str,
) -> str:
    evidence_blob = "\n".join(vulnerability.evidence or [])
    text = f"{vulnerability.title}\n{vulnerability.description}\n{observed}\n{evidence_blob}"
    if re.search(r"\buid=0\b|whoami.*root|root\s*权限", text, re.IGNORECASE):
        return "An attacker can gain system-level command execution and may be able to take higher-privileged control"
    if re.search(r"www-data|whoami.*www-data|interactive shell", text, re.IGNORECASE):
        return "An attacker can execute commands as the web process and continue toward system privileges"
    if vuln_type in {"Path traversal", "Broken access control", "Information disclosure"}:
        return "An attacker can read another user's results, internal files, or sensitive business data without authorization"
    if vuln_type == "SQL injection":
        return "An attacker can cross the normal data-access boundary and read, modify, or otherwise affect database data"
    if vuln_type == "File upload":
        return "An attacker can bring an unsafe file into server-side processing and may reach code execution or file write"
    if vuln_type in {"Command injection", "Remote code execution", "Deserialization"}:
        return "An attacker can push external input into a server execution path and gain high-impact control of the host or application"
    return f"This issue creates a verifiable exposure. Observed result: {observed}"


def _observed_result(vulnerability: Vulnerability, context: _ReportContext) -> str:
    candidates = []
    candidates.extend(vulnerability.evidence or [])
    candidates.append(vulnerability.description)
    candidates.extend(description for _fact_id, description in context.related_facts)
    for packet in vulnerability.proof_packets or []:
        response = str(packet.get("response") or "").strip()
        if response:
            candidates.append(response)
    positive = [
        item
        for item in candidates
        if re.search(
            r"返回\s*200|\b200\b|whoami|uid=|www-data|root|直接返回|成功|回显|正文为|读取|泄露|application/",
            item,
            re.IGNORECASE,
        )
    ]
    source = positive[0] if positive else (candidates[0] if candidates else "The material does not record a stable response")
    return _first_line(source, 220)


def _parameter_names(text: str, proof_packets: list[dict[str, str]]) -> list[str]:
    params: list[str] = []
    seen: set[str] = set()
    for packet in proof_packets:
        request = str(packet.get("request") or "")
        target = _request_target(packet)
        if target and "?" in target:
            for key, _value in parse_qsl(target.split("?", 1)[1], keep_blank_values=True):
                key = key.strip()
                if key and key not in seen:
                    seen.add(key)
                    params.append(key)
        if "\n\n" in request:
            body = request.split("\n\n", 1)[1]
            for key, _value in parse_qsl(body, keep_blank_values=True):
                key = key.strip()
                if key and key not in seen:
                    seen.add(key)
                    params.append(key)
    for match in re.finditer(r"(?<![\w.-])([A-Za-z_][\w.\[\]-]{0,80})=([^\s&]+)", text):
        key = match.group(1).strip()
        # Exclude id-command output fields (uid/gid/euid/groups/context/sid)
        # and common non-parameter keys, so RCE proof text isn't misread as
        # HTTP parameters.
        if key.lower() in {"http", "https", "host", "uid", "gid", "euid", "groups", "context", "sid"} or key in seen:
            continue
        seen.add(key)
        params.append(key)
    for match in re.finditer(r"(?:上传字段|字段|参数)[:：]\s*([A-Za-z_][\w.\[\]-]{0,80})", text):
        key = match.group(1).strip()
        if key and key not in seen:
            seen.add(key)
            params.append(key)
    return params[:8]


def _attack_surface_lines(vulnerability: Vulnerability) -> list[str]:
    return [packet.get("title") or "" for packet in (vulnerability.proof_packets or [])]


def _extract_paths(text: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    patterns = (
        r"https?://[^\s`'\"<>，。；;）)]+",
        r"(?<![\w./:])/(?!/)[A-Za-z0-9._~!$&'()*+,;=:@%/?#\[\]-]+",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            raw = match.group(0)
            if raw.lower().startswith(("http://", "https://")):
                parsed = urlsplit(raw)
                raw = parsed.path or "/"
                if parsed.query:
                    raw += "?" + parsed.query
            cleaned = raw.strip(_TRAILING_PUNCTUATION)
            if not cleaned.startswith("/") or cleaned.startswith("//") or cleaned in seen:
                continue
            if cleaned.startswith(_FILESYSTEM_PREFIXES):
                # Local workspace paths (scripts, tool caches) are not
                # attack-surface endpoints.
                continue
            seen.add(cleaned)
            values.append(cleaned)
    return values[:8]


def _request_target(packet: dict[str, str]) -> str:
    request = str(packet.get("request") or "").strip()
    if not request:
        return ""
    first_line = request.splitlines()[0].strip()
    parts = first_line.split()
    if len(parts) >= 2 and parts[1].startswith("/"):
        return parts[1].strip()
    return ""


def _evidence_highlights(
    vulnerability: Vulnerability,
    context: _ReportContext,
) -> list[str]:
    candidates = _unique(
        [
            *_attack_surface_lines(vulnerability),
            *(vulnerability.evidence or []),
            *[description for _fact_id, description in context.related_facts],
            vulnerability.description,
        ]
    )
    scored = sorted(candidates, key=_evidence_score, reverse=True)
    return [_first_line(item, 220) for item in scored[:6] if item]


def _remediation(vuln_type: str) -> list[str]:
    mapping = {
        "Command injection": [
            "Do not concatenate external input into a shell command. Use a parameterized execution API and disable shell=True.",
            "Allowlist commands, scripts, task names, and paths, and enforce the boundary on the server.",
            "Add audit logs and least privilege on high-risk execution paths so the web process does not hold high-value system rights.",
        ],
        "SQL injection": [
            "Replace dynamic SQL with parameterized queries or prepared statements.",
            "Allowlist query conditions and sort fields. Do not place arbitrary controllable fields into SQL.",
            "Apply least database privilege and exception auditing to limit the blast radius of one injection.",
        ],
        "Deserialization": [
            "Do not deserialize untrusted input. Prefer a safe data format.",
            "If complex objects must be parsed, restrict the allowed types and verify the data source.",
            "Remove dangerous gadget dependencies or disable automatic loading at runtime.",
        ],
        "File upload": [
            "Rename uploads on the server and store them outside the parser directory. Do not land a user-controlled filename in a parsed path.",
            "Check MIME type, extension, and content signature together so one check cannot be bypassed.",
            "Isolate the upload directory and the follow-on processor so a parsed file is not executed directly.",
        ],
        "Path traversal": [
            "Normalize access paths, confine them to the intended directory, and reject directory-traversal segments.",
            "Do not trust user-supplied relative paths, archive member names, or file references.",
            "Add object-level authorization on readable resources so one user or task cannot read another.",
        ],
        "Broken access control": [
            "Require authentication and object-level authorization at the endpoint. Do not rely on hiding controls in the UI.",
            "Check ownership before reading or downloading projects, tasks, files, and similar resources.",
            "Monitor high-value endpoints for unauthorized access and unusual request rates.",
        ],
        "SSRF": [
            "Restrict protocols, hostnames, and address ranges the server may contact, including internal and metadata addresses.",
            "Validate the resolved target address to resist DNS rebinding and protocol bypasses.",
            "Use a least-privilege egress policy and audit unusual outbound requests.",
        ],
        "XXE": [
            "Disable external entities, DTDs, and network loading in the XML parser.",
            "If XML is required, use a safe parse mode and limit document size.",
            "Validate and isolate uploaded or imported XML.",
        ],
        "Cross-site scripting": [
            "Encode output for the HTML, attribute, or script context instead of reflecting controllable content.",
            "Use one filtering policy for rich text and template variables, and add a CSP.",
            "Clean stored malicious content so it cannot keep firing.",
        ],
        "Information disclosure": [
            "Restrict sensitive endpoints, debug output, and internal status pages. Do not expose them by default.",
            "Remove unnecessary internal paths, versions, credential clues, and business details from responses.",
            "Apply least exposure and role-based access so anonymous callers cannot read sensitive content.",
        ],
        "Remote code execution": [
            "Remove direct control of execution paths by external input, and allowlist the remaining high-risk execution points.",
            "Run components that can execute code with least privilege and isolation so a break does not own the host.",
            "Audit process creation and alert when an execution path is reached.",
        ],
    }
    return mapping.get(
        vuln_type,
        [
            "Trace the processing path this issue hits, identify where external input enters, and add a boundary check.",
            "Add least privilege, input constraints, and exception auditing on the related endpoints.",
            "Add a regression test after the fix so the same attack surface cannot be bypassed the same way.",
        ],
    )


def _extract_json_payload(text: str) -> Any:
    candidate = text.strip()
    if candidate.startswith("```"):
        candidate = re.sub(r"^```(?:json)?\s*", "", candidate)
        candidate = re.sub(r"\s*```$", "", candidate)
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", candidate, re.S)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None


def _evidence_score(value: str) -> tuple[int, int]:
    score = 0
    for pattern, weight in (
        (r"whoami|uid=|root|www-data|interactive shell", 80),
        (r"返回\s*200|\b200\b|直接返回|正文为|回显|Content-Type", 40),
        (r"已确认|真实存在|证明", 30),
        (r"失败|不可利用|未观察到|未发现|尚未", -60),
    ):
        if re.search(pattern, value, re.IGNORECASE):
            score += weight
    return (score, len(value))


def _first_line(value: str, limit: int) -> str:
    text = next((line.strip() for line in str(value or "").splitlines() if line.strip()), "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _string_list(values: list[Any]) -> list[str]:
    result: list[str] = []
    for item in values:
        text = str(item or "").strip()
        if text:
            result.append(text)
    return result[:8]


def _trim(value: str, limit: int) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        text = str(item or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _severity_label(severity: str) -> str:
    return {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }.get(severity, severity)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
