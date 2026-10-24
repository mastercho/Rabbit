"""Project-level campaign synthesis derived from native Cairn-Y state."""

from __future__ import annotations

import re
from dataclasses import dataclass

from cairn.server.campaign_models import (
    CampaignCounts,
    CampaignFinding,
    CampaignGoalStatus,
    CampaignSynthesis,
)
from cairn.server.db import get_conn
from cairn.server.text_normalization import normalize_hint_content
from cairn.server.services import expire_decide_leases, expire_workers, get_project_or_404


@dataclass(frozen=True)
class _LoadedVulnerability:
    id: str
    fact_id: str
    title: str
    description: str
    severity: str
    status: str
    discovered_at: str


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

_POSITIVE_FACT_PATTERNS: tuple[tuple[str, int], ...] = (
    (r"\buid=0\b", 120),
    (r"\buid=\d+\([^)]+\)\b", 110),
    (r"\bwww-data\b", 90),
    (r"\bwhoami\b", 80),
    (r"远程(?:代码|命令)?执行|命令执行|rce", 75),
    (r"未授权\s*(?:读取|访问)|越权读取|跨作业读取", 70),
    (r"路径穿越|directory traversal|path traversal", 65),
    (r"返回\s*200|Content-Type|正文为|页面标题为|解包确认", 35),
    (r"已确认|真实存在|证明攻击者可|证明可|直接返回|暴露|泄露", 30),
)

_NEGATIVE_FACT_PATTERNS: tuple[tuple[str, int], ...] = (
    (r"未观察到(?:任何)?真实(?:执行|利用|命令执行)证据", 90),
    (r"未发现.{0,80}(?:uid=|www-data|whoami|id\s*输出|副作用)", 80),
    (r"尚不能(?:据此)?确认|不能(?:据此)?确认", 70),
    (r"无命令执行|不可利用|未触发|未命中|无可利用", 60),
    (r"失败|超时|未获得|未收到", 30),
)


def build_campaign_synthesis(project_id: str) -> CampaignSynthesis:
    with get_conn() as conn:
        expire_workers(conn, project_id)
        expire_decide_leases(conn, project_id)
        project = get_project_or_404(conn, project_id)
        fact_rows = conn.execute(
            "SELECT id, description FROM facts WHERE project_id = ? ORDER BY rowid",
            (project_id,),
        ).fetchall()
        hint_rows = conn.execute(
            "SELECT id, content FROM hints WHERE project_id = ? ORDER BY created_at, rowid",
            (project_id,),
        ).fetchall()
        goal_rows = conn.execute(
            """
            SELECT id, description, parent_goal_id, status, priority
            FROM goals
            WHERE project_id = ?
            ORDER BY priority DESC, created_at, rowid
            """,
            (project_id,),
        ).fetchall()
        step_rows = conn.execute(
            """
            SELECT id, description, concluded_at, abandoned
            FROM steps
            WHERE project_id = ?
            ORDER BY priority DESC, created_at, rowid
            """,
            (project_id,),
        ).fetchall()
        vulnerability_rows = conn.execute(
            """
            SELECT id, fact_id, title, description, severity, status, discovered_at
            FROM vulnerabilities
            WHERE project_id = ?
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 3
                    ELSE 4
                END,
                discovered_at DESC,
                id DESC
            """,
            (project_id,),
        ).fetchall()

    facts = [(row["id"], str(row["description"] or "").strip()) for row in fact_rows]
    fact_by_id = {fact_id: description for fact_id, description in facts}
    hints = [(row["id"], normalize_hint_content(row["content"])) for row in hint_rows]
    open_steps = [
        str(row["description"] or "").strip()
        for row in step_rows
        if row["concluded_at"] is None
        and not bool(row["abandoned"])
        and str(row["description"] or "").strip()
    ]
    vulnerabilities = [
        _LoadedVulnerability(
            id=row["id"],
            fact_id=row["fact_id"],
            title=str(row["title"] or "").strip(),
            description=str(row["description"] or "").strip(),
            severity=str(row["severity"] or "").strip(),
            status=str(row["status"] or "confirmed").strip(),
            discovered_at=str(row["discovered_at"] or "").strip(),
        )
        for row in vulnerability_rows
    ]

    counts = CampaignCounts(
        facts=len(facts),
        hints=len(hints),
        goals=len(goal_rows),
        steps=len(step_rows),
        open_steps=len(open_steps),
        intents=len(step_rows),
        open_intents=len(open_steps),
        vulnerabilities=len(vulnerabilities),
        high_value_vulnerabilities=sum(
            1
            for vuln in vulnerabilities
            if vuln.status == "confirmed" and vuln.severity in {"critical", "high"}
        ),
    )
    goal_status = _goal_status(project["status"], goal_rows, facts, open_steps, vulnerabilities)
    top_findings = _top_findings(facts, hints, vulnerabilities)
    blockers = _blockers(facts)
    lead = _lead(project["title"], goal_status, vulnerabilities, top_findings, open_steps)
    summary = _summary(project["title"], project["status"], goal_status, counts, lead, blockers)
    next_steps = _next_steps(goal_status, counts, open_steps, hints, vulnerabilities)

    top_level_goals = [row for row in goal_rows if row["parent_goal_id"] is None]
    goal_text = "\n".join(str(row["description"] or "").strip() for row in top_level_goals)

    return CampaignSynthesis(
        project_id=project["id"],
        project_name=project["title"],
        project_status=project["status"],
        goal_status=goal_status,
        origin=fact_by_id.get("origin", ""),
        goal=goal_text or fact_by_id.get("goal", ""),
        lead=lead,
        summary=summary,
        counts=counts,
        top_findings=top_findings,
        open_steps=open_steps[:5],
        open_intents=open_steps[:5],
        blockers=blockers,
        next_steps=next_steps,
    )


def _goal_status(
    project_status: str,
    goals,
    facts: list[tuple[str, str]],
    open_steps: list[str],
    vulnerabilities: list[_LoadedVulnerability],
) -> CampaignGoalStatus:
    if goals:
        if all(str(goal["status"]) == "completed" for goal in goals):
            return "achieved"
        if project_status == "completed":
            return "achieved"
        if open_steps or len(facts) > 1 or vulnerabilities:
            return "in_progress"
        return "blocked"

    # Compatibility for pre-migration test fixtures and exported legacy data.
    text = "\n".join(description for _fact_id, description in facts)
    # Positive success signals: command-execution proof that the goal
    # (server access / whoami / ifconfig / shell) has been achieved.
    # NOTE: the trailing `\b` after `)` in the old pattern failed to match
    # `uid=33(www-data)` because there is no word boundary between `)` and
    # whitespace/EOB. The parenthesized form is now matched without `\b`,
    # and we also accept plain `uid=N`, ifconfig output, webshell response,
    # and goal-achieved/cve-marked-as-achieved statements.
    has_positive_success = bool(
        re.search(
        r"\buid=0\b|"
        r"uid=\d+\((?:root|www-data|daemon|nobody)\)|"
        r"\bwhoami\b[^.\n]{0,20}\b(?:root|www-data|daemon|nobody)\b|"
        r"connected\s+as\s+(?:root|www-data)|"
        r"interactive\s+shell\s+ready|"
        r"\bifconfig\b[^.\n]{0,80}\b(?:inet|ether|HWaddr|flags)\b|"
        r"(?:目标已达成|goal\s*已达成|已拿到\s*(?:webshell|shell|权限))|"
        r"\b(?:webshell|shell)\s*(?:已部署|部署成功|可访问|ready)",
        text,
        re.IGNORECASE,
        )
    )
    if has_positive_success:
        return "achieved"
    if any(vuln.status == "confirmed" and vuln.severity in {"critical", "high"} for vuln in vulnerabilities):
        return "in_progress"

    score = _fact_score(text)
    if score >= 70:
        return "in_progress"
    return "blocked"


def _fact_score(text: str) -> int:
    score = 0
    for pattern, weight in _POSITIVE_FACT_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            score += weight
    for pattern, weight in _NEGATIVE_FACT_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            score -= weight
    return score


def _first_line(text: str, limit: int = 180) -> str:
    snippet = next((line.strip() for line in text.splitlines() if line.strip()), "").strip()
    if len(snippet) <= limit:
        return snippet
    return snippet[: limit - 3].rstrip() + "..."


def _fact_confidence(score: int) -> str:
    if score >= 90:
        return "confirmed"
    if score >= 40:
        return "supported"
    return "tentative"


def _top_findings(
    facts: list[tuple[str, str]],
    hints: list[tuple[str, str]],
    vulnerabilities: list[_LoadedVulnerability],
) -> list[CampaignFinding]:
    findings: list[CampaignFinding] = []
    covered_fact_ids = {vuln.fact_id for vuln in vulnerabilities}

    for vuln in vulnerabilities[:3]:
        findings.append(
            CampaignFinding(
                source_type="vulnerability",
                source_id=vuln.id,
                title=vuln.title,
                summary=_first_line(vuln.description),
                severity=vuln.severity if vuln.severity in _SEVERITY_RANK else None,
                confidence="confirmed" if vuln.status == "confirmed" else "supported",
            )
        )

    scored_facts = sorted(
        (
            (fact_id, description, _fact_score(description))
            for fact_id, description in facts
            if fact_id not in {"origin", "goal"} and fact_id not in covered_fact_ids
        ),
        key=lambda item: (item[2], _fact_numeric_rank(item[0])),
        reverse=True,
    )
    for fact_id, description, score in scored_facts:
        if score < 25 or len(findings) >= 5:
            continue
        findings.append(
            CampaignFinding(
                source_type="fact",
                source_id=fact_id,
                title=_first_line(description, limit=84) or fact_id,
                summary=_first_line(description),
                confidence=_fact_confidence(score),
            )
        )

    if not findings and hints:
        hint_id, hint_text = hints[-1]
        findings.append(
            CampaignFinding(
                source_type="hint",
                source_id=hint_id,
                title="Latest hint",
                summary=_first_line(hint_text),
                confidence="tentative",
            )
        )

    return findings


def _fact_numeric_rank(fact_id: str) -> int:
    match = re.search(r"(\d+)", fact_id)
    return int(match.group(1)) if match else -1


def _blockers(facts: list[tuple[str, str]]) -> list[str]:
    blockers: list[tuple[int, str]] = []
    for fact_id, description in facts:
        if fact_id in {"origin", "goal"}:
            continue
        if not any(re.search(pattern, description, re.IGNORECASE) for pattern, _ in _NEGATIVE_FACT_PATTERNS):
            continue
        blockers.append((_fact_numeric_rank(fact_id), _first_line(description)))

    blockers.sort(reverse=True)
    unique: list[str] = []
    seen: set[str] = set()
    for _rank, blocker in blockers:
        if not blocker or blocker in seen:
            continue
        seen.add(blocker)
        unique.append(blocker)
        if len(unique) >= 3:
            break
    return unique


def _lead(
    project_name: str,
    goal_status: CampaignGoalStatus,
    vulnerabilities: list[_LoadedVulnerability],
    top_findings: list[CampaignFinding],
    open_steps: list[str],
) -> str:
    if goal_status == "achieved":
        return f"{project_name} has results that are strong enough to show the goal was achieved."
    if vulnerabilities:
        head = vulnerabilities[0]
        severity = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}.get(
            head.severity,
            head.severity,
        )
        return f"The campaign has converged on a {severity} finding: {head.title}"
    if top_findings:
        return f"The strongest signal is {top_findings[0].source_id}: {top_findings[0].title}"
    if open_steps:
        return f"The main open step is still {open_steps[0]}."
    return f"{project_name} does not yet have a strong project-level signal."


def _summary(
    project_name: str,
    project_status: str,
    goal_status: CampaignGoalStatus,
    counts: CampaignCounts,
    lead: str,
    blockers: list[str],
) -> str:
    parts = [
        f"Project {project_name} is {project_status}. Goal status: {goal_status}.",
        lead,
        f"So far: {counts.facts} facts, {counts.goals} goals, {counts.open_steps} open steps, {counts.vulnerabilities} findings, including {counts.high_value_vulnerabilities} high-value findings.",
    ]
    if project_status == "completed" and goal_status != "achieved":
        parts.append("The project is marked completed, but the facts still lack a direct success signal that the goal was achieved.")
    if blockers:
        parts.append(f"Latest blocker: {blockers[0]}")
    return " ".join(parts)


def _next_steps(
    goal_status: CampaignGoalStatus,
    counts: CampaignCounts,
    open_steps: list[str],
    hints: list[tuple[str, str]],
    vulnerabilities: list[_LoadedVulnerability],
) -> list[str]:
    if goal_status == "achieved":
        return [
            "Freeze the key evidence and the smallest reproduction so later facts do not overwrite the successful conclusion.",
            "Keep the project conclusion separate from individual facts so both the conclusion and the evidence stay traceable.",
        ]

    steps: list[str] = []
    if vulnerabilities:
        steps.append("Keep confirmed high-value findings separate from unverified privilege paths so one fact does not carry both conclusions.")
    else:
        steps.append("Turn the strongest signals into a project conclusion so scattered facts do not sit on the graph without a campaign judgment.")

    if open_steps:
        steps.append("Close the open steps before recording more similar negative results on the same lead.")
    else:
        steps.append("There are no open steps. Decide should add a few non-overlapping next steps from the goal and the latest facts.")

    if hints:
        steps.append("Keep the original wording and raw request details of key hints so later reproductions do not drift.")

    if counts.high_value_vulnerabilities == 0:
        steps.append("Record reproducible boundaries, evidence, and failure conditions before narrowing the goal to a single success criterion.")

    return steps[:4]
