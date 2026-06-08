"""
IAM Policy Engine — real Allow/Deny evaluation.

Evaluates IAM policies against (principal, action, resource) tuples.
Follows the AWS evaluation logic:

    1. Explicit Deny  → DENY  (wins over everything)
    2. Explicit Allow → ALLOW
    3. No match      → IMPLICIT DENY

Supports wildcard matching for Action and Resource patterns.
Conditions are not yet evaluated (too complex for initial pass).
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger("iam.policy")

# ---------------------------------------------------------------------------
# Pattern matching
# ---------------------------------------------------------------------------

_WILDCARD_RE = re.compile(r"[*?]")


def _glob_to_regex(pattern: str) -> str:
    """Convert an AWS wildcard pattern to a regex.

    ``*`` matches zero or more characters.
    ``?`` matches exactly one character.
    Everything else is escaped for literal match.

    >>> _glob_to_regex("s3:*")
    's3:.*'
    >>> _glob_to_regex("ec2:Describe*")
    'ec2:Describe.*'
    """
    if not _WILDCARD_RE.search(pattern):
        return f"^{re.escape(pattern)}$"
    # Build regex: split on wildcards, escape literal parts
    parts: list[str] = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            parts.append(".*")
            i += 1
        elif c == "?":
            parts.append(".")
            i += 1
        else:
            # Collect literal run
            j = i
            while j < len(pattern) and pattern[j] not in "*?":
                j += 1
            parts.append(re.escape(pattern[i:j]))
            i = j
    return "^" + "".join(parts) + "$"


def action_matches(pattern: str, action: str) -> bool:
    """Check if an IAM Action pattern matches a concrete action.

    ``*`` matches all actions.
    ``service:*`` matches all actions within a service.
    ``service:Prefix*`` matches actions starting with a prefix.

    >>> action_matches("ec2:*", "ec2:RunInstances")
    True
    >>> action_matches("ec2:Describe*", "ec2:DescribeInstances")
    True
    >>> action_matches("ec2:*", "s3:GetObject")
    False
    """
    return bool(re.match(_glob_to_regex(pattern), action))


def resource_matches(pattern: str, resource: str) -> bool:
    """Check if an IAM Resource pattern matches a concrete resource ARN.

    ``*`` matches all resources.
    ``arn:aws:ec2:*:*:instance/*`` matches any EC2 instance.
    ``arn:aws:s3:::my-bucket/*`` matches objects in a specific bucket.

    >>> resource_matches("*", "arn:aws:ec2:us-east-1:000000000000:instance/i-123")
    True
    >>> resource_matches("arn:aws:ec2:*:*:instance/*", "arn:aws:ec2:us-east-1:000000000000:instance/i-123")
    True
    >>> resource_matches("arn:aws:s3:::my-bucket/*", "arn:aws:ec2:us-east-1:000000000000:instance/i-123")
    False
    """
    return bool(re.match(_glob_to_regex(pattern), resource))


# ---------------------------------------------------------------------------
# Policy evaluation
# ---------------------------------------------------------------------------


def evaluate(statements: list[dict], action: str, resource: str) -> str:
    """Evaluate a list of policy statements against an action and resource.

    Args:
        statements: List of statement dicts, each with ``Effect``,
                    ``Action``, and ``Resource`` keys.
                    ``Action`` can be a string or list of strings.
                    ``Resource`` can be a string or list of strings.
        action: The concrete action being attempted (e.g. ``ec2:RunInstances``).
        resource: The concrete resource ARN (e.g. ``arn:aws:ec2:...:instance/i-xxx``).

    Returns:
        ``"deny"`` if any explicit Deny matches.
        ``"allow"`` if any explicit Allow matches (and no Deny).
        ``"implicit_deny"`` if no statement matches at all.
    """
    explicit_deny = False
    explicit_allow = False

    for stmt in statements:
        effect = stmt.get("Effect", "")
        if effect not in ("Allow", "Deny"):
            continue

        stmt_actions = stmt.get("Action", [])
        if isinstance(stmt_actions, str):
            stmt_actions = [stmt_actions]

        stmt_resources = stmt.get("Resource", [])
        if isinstance(stmt_resources, str):
            stmt_resources = [stmt_resources]

        # Check if this statement matches our action AND resource
        action_match = any(action_matches(pat, action) for pat in stmt_actions)
        resource_match = any(resource_matches(pat, resource) for pat in stmt_resources)

        if action_match and resource_match:
            if effect == "Deny":
                explicit_deny = True
            elif effect == "Allow":
                explicit_allow = True

    if explicit_deny:
        return "deny"
    if explicit_allow:
        return "allow"
    return "implicit_deny"


# ---------------------------------------------------------------------------
# Statement collection (for use by IAM service)
# ---------------------------------------------------------------------------


def collect_statements(
    principal_name: str,
    principal_type: str,  # "user" | "role"
    policies: dict,         # all policies {name: record}
    user_policies: dict,    # {username: [policy_name, ...]}
    role_policies: dict,    # {rolename: [policy_name, ...]}
    groups: dict,           # {groupname: [username, ...]}
    group_policies: dict,   # {groupname: [policy_name, ...]}
    user_inline_policies: dict,  # {(account_id, username): {policy_name: policy_doc}}
    role_inline_policies: dict,  # {(account_id, rolename): {policy_name: policy_doc}}
) -> list[dict]:
    """Collect all policy statements applicable to a principal.

    Includes:
    1. Attached managed policies
    2. Group policies (users only)
    3. Inline policies
    """
    statements: list[dict] = []

    # 1. Attached managed policies
    attached = user_policies.get(principal_name, []) if principal_type == "user" \
        else role_policies.get(principal_name, [])
    for pname in attached:
        policy = policies.get(pname, {})
        for stmt in _statements_from_policy(policy):
            statements.append(stmt)

    # 2. Group policies (users only)
    if principal_type == "user":
        for gname, members in groups.items():
            if principal_name in members:
                for pname in group_policies.get(gname, []):
                    policy = policies.get(pname, {})
                    for stmt in _statements_from_policy(policy):
                        statements.append(stmt)

    # 3. Inline policies
    is_user = principal_type == "user"
    inline_dict = user_inline_policies if is_user else role_inline_policies
    # Inline policies are stored per (account, name)
    for (account, name), inline_pols in inline_dict.items():
        if name == principal_name:
            for _pname, doc in inline_pols.items():
                if isinstance(doc, str):
                    import json
                    doc = json.loads(doc)
                for stmt in doc.get("Statement", []):
                    statements.append(stmt)

    return statements


def _statements_from_policy(policy: dict) -> list[dict]:
    """Extract statements from a policy record (which may have versions)."""
    # Try versioned format first
    versions = policy.get("Versions", {})
    if versions:
        default_ver = policy.get("DefaultVersionId", "")
        ver = versions.get(default_ver, list(versions.values())[0] if versions else {})
        doc = ver.get("Document", "")
        if isinstance(doc, str):
            import json
            doc = json.loads(doc)
        return doc.get("Statement", [])
    # Try flat format
    doc = policy.get("PolicyDocument", "")
    if isinstance(doc, str):
        import json
        doc = json.loads(doc)
    if isinstance(doc, dict):
        return doc.get("Statement", [])
    return []
