"""Built-in project templates for the Template Engine.

This module is intentionally a standalone module (``templates_service.py``)
rather than a ``services/templates.py`` package member. The existing
``cairn.server.services`` is a single module (``services.py``) imported across
the server (``from cairn.server.services import ...``); introducing a
``services/`` package would shadow that module and break those core imports. So
this additive service lives alongside ``finding_projection.py`` and
``templates_models.py`` instead, mirroring the convention already established in
this package.

Built-in templates are defined as an in-memory Python constant rather than being
stored in the database (see design.md, "Template Engine" / "Built-in
Templates"). Only user-created custom templates are persisted (in the
``templates`` table created by the product schema). The templates router merges
this constant list with a user's stored custom templates when answering
``GET /api/templates``.

Each built-in template satisfies requirements 12.1 and 12.2:

* 12.1 -- at minimum the four templates Web Application Assessment, Internal
  Network Pentest, External Network Pentest, and CTF Challenge are provided.
* 12.2 -- each template carries a title, an ``origin`` fact, a ``goal`` fact, and
  between 1 and 10 initial ``hints`` where every hint is a ``{content, creator}``
  mapping whose ``creator`` is ``"template"``.

The shapes mirror :class:`cairn.server.templates_models.TemplateResponse`:
built-in templates use ``is_builtin=True`` and leave ``user_id`` as ``None``.
"""

from __future__ import annotations

# Marker stored in every built-in hint's ``creator`` field (requirement 12.2).
TEMPLATE_CREATOR = "template"


def _hint(content: str) -> dict[str, str]:
    """Build a ``{content, creator}`` hint with the template creator marker."""
    return {"content": content, "creator": TEMPLATE_CREATOR}


# The built-in templates surfaced by the Template Engine. Each entry mirrors the
# ``TemplateResponse`` shape (``is_builtin=True``, ``user_id=None``) so the
# templates router can return built-in and custom templates through one model.
BUILTIN_TEMPLATES: list[dict] = [
    {
        "id": "builtin-web-app",
        "title": "Web application assessment",
        "origin": "Target web application at [URL], technology stack [technology stack]",
        "goal": "Identify and record exploitable vulnerabilities in the web application",
        "hints": [
            _hint(
                "Start with reconnaissance: enumerate subdomains, directories, and technologies"
            ),
            _hint("Test whether authentication can be bypassed"),
            _hint("Check user input for injection points"),
        ],
        "is_builtin": True,
        "user_id": None,
    },
    {
        "id": "builtin-internal-network",
        "title": "Internal network assessment",
        "origin": "Internal network [CIDR] reachable from an assumed foothold",
        "goal": "Reach domain control and record lateral movement and privilege escalation",
        "hints": [
            _hint(
                "Enumerate live hosts and services on the internal segment"
            ),
            _hint(
                "Identify Active Directory assets: domain controllers, users, and groups"
            ),
            _hint(
                "Search shares, scripts, and service configuration for credentials"
            ),
            _hint(
                "Map lateral movement and privilege escalation toward domain admin"
            ),
        ],
        "is_builtin": True,
        "user_id": None,
    },
    {
        "id": "builtin-external-network",
        "title": "External network assessment",
        "origin": "[organization] internet-facing assets: in-scope IP ranges and domains",
        "goal": "Find and verify exposed services to gain an initial foothold",
        "hints": [
            _hint(
                "Enumerate the external attack surface: open ports, services, and exposed applications"
            ),
            _hint(
                "Fingerprint service versions and check for known exploitable weaknesses"
            ),
            _hint(
                "Test exposed logins for weak or default credentials"
            ),
            _hint(
                "Check TLS configuration and certificates for misconfiguration"
            ),
        ],
        "is_builtin": True,
        "user_id": None,
    },
    {
        "id": "builtin-ctf",
        "title": "CTF challenge",
        "origin": "CTF target at [host:port], category [web/pwn/crypto/forensics]",
        "goal": "Solve the challenge and capture the flag",
        "hints": [
            _hint("Identify the challenge category and collect the provided files or endpoints"),
            _hint("Probe for the weakness class expected in that category"),
            _hint("Develop a verification or solution and capture the flag"),
        ],
        "is_builtin": True,
        "user_id": None,
    },
]
