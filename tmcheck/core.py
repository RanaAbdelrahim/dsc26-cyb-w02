"""tmcheck: a checker for threat models kept as YAML in the repository.

Fill in every function. Keep the names and signatures exactly as they are: the grader imports them.
The full rules are in README.md ("What to build").
"""
from __future__ import annotations

from dataclasses import dataclass
import yaml


class ModelError(Exception):
    """The file cannot be read as a threat model."""


@dataclass(frozen=True, order=True)
class Issue:
    ref: str          # id of the zone/element/flow/threat the issue is about
    code: str
    message: str = ""


@dataclass(frozen=True, order=True)
class Gap:
    ref: str          # element or flow id
    category: str     # one STRIDE letter


@dataclass(frozen=True)
class RankedThreat:
    id: str
    score: int
    level: str        # "high" | "medium" | "low"



def load_model(path) -> dict:
    """Read and validate a YAML threat model."""
    try:
        with open(path, "r", encoding="utf-8") as file:
            model = yaml.safe_load(file)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ModelError(f"Cannot load model: {exc}") from exc

    if not isinstance(model, dict):
        raise ModelError("The model must be a YAML mapping.")

    for section in ("zones", "elements", "flows", "threats"):
        if model.get(section) is None:
            model[section] = []
        elif not isinstance(model[section], list):
            raise ModelError(f"Section '{section}' must be a list.")

    return model



def applicable(kind: str, *, is_log: bool = False) -> set[str]:
    if kind == "external_entity":
        return {"S", "R"}

    if kind == "process":
        return {"S", "T", "R", "I", "D", "E"}

    if kind == "data_store":
        categories = {"T", "I", "D"}
        if is_log:
            categories.add("R")
        return categories

    if kind == "data_flow":
        return {"T", "I", "D"}

    raise ValueError(f"Unknown element kind: {kind}")



def validate(model: dict) -> list[Issue]:
    issues = set()
    zones = {}
    elements = {}
    flows = {}
    threats = {}

    # Check for duplicate IDs across all four sections.
    seen_ids = set()

    for section in ("zones", "elements", "flows", "threats"):
        for item in model.get(section, []):
            item_id = item.get("id")
            if item_id is not None:
                if item_id in seen_ids:
                    issues.add(Issue(item_id, "DUPLICATE_ID"))
                seen_ids.add(item_id)

    zones = {
        item["id"]: item
        for item in model.get("zones", [])
        if "id" in item
    }
    elements = {
        item["id"]: item
        for item in model.get("elements", [])
        if "id" in item
    }
    flows = {
        item["id"]: item
        for item in model.get("flows", [])
        if "id" in item
    }

    # Validate elements.
    valid_kinds = {"external_entity", "process", "data_store"}

    for element in model.get("elements", []):
        ref = element.get("id", "")
        kind = element.get("kind")

        if kind not in valid_kinds:
            issues.add(Issue(ref, "BAD_KIND"))
        if element.get("zone") not in zones:
            issues.add(Issue(ref, "UNKNOWN_ZONE"))

    # Validate flows.
    for flow in model.get("flows", []):
        ref = flow.get("id", "")
        source_id = flow.get("source")
        target_id = flow.get("target")

        source = elements.get(source_id)
        target = elements.get(target_id)

        if source is None or target is None:
            issues.add(Issue(ref, "UNKNOWN_REF"))
            continue

        if (
            source_id == target_id
            or source.get("kind") != "process"
            and target.get("kind") != "process"
        ):
            issues.add(Issue(ref, "INVALID_FLOW"))

    # Validate threats.
    valid_categories = {"S", "T", "R", "I", "D", "E"}
    valid_statuses = {"open", "mitigated", "accepted"}

    for threat in model.get("threats", []):
        ref = threat.get("id", "")
        target_id = threat.get("target")
        category = threat.get("category")
        status = threat.get("status")

        target = elements.get(target_id)
        if target is None:
            target = flows.get(target_id)

        if target is None:
            issues.add(Issue(ref, "UNKNOWN_REF"))

        if category not in valid_categories:
            issues.add(Issue(ref, "BAD_CATEGORY"))
        elif target is not None:
            if target_id in elements:
                kind = target.get("kind")

                if kind not in valid_kinds:
                    allowed = None
                else:
                    allowed = applicable(
                        kind,
                        is_log=target.get("is_log", False),
                    )
            else:
                allowed = applicable("data_flow")

            if allowed is not None and category not in allowed:
                issues.add(Issue(ref, "INAPPLICABLE_CATEGORY"))

        for field in ("likelihood", "impact"):
            score = threat.get(field)
            if type(score) is not int or not 1 <= score <= 5:
                issues.add(Issue(ref, "BAD_SCORE"))

        if status not in valid_statuses:
            issues.add(Issue(ref, "BAD_STATUS"))
        elif status == "mitigated" and not (
            isinstance(threat.get("mitigation"), str)
            and threat["mitigation"].strip()
        ):
            issues.add(Issue(ref, "MISSING_MITIGATION"))
        elif status == "accepted" and not (
            isinstance(threat.get("justification"), str)
            and threat["justification"].strip()
        ):
            issues.add(Issue(ref, "MISSING_JUSTIFICATION"))

    return sorted(issues, key=lambda issue: (issue.ref, issue.code, issue.message))



def crossing_flows(model: dict) -> list[str]:
    elements = {
        element["id"]: element
        for element in model.get("elements", [])
        if "id" in element
    }

    result = []

    for flow in model.get("flows", []):
        source = elements.get(flow.get("source"))
        target = elements.get(flow.get("target"))

        if source is None or target is None:
            continue

        if source.get("zone") != target.get("zone"):
            result.append(flow["id"])

    return result



def coverage_gaps(model: dict) -> list[Gap]:
    stride_order = {"S": 0, "T": 1, "R": 2, "I": 3, "D": 4, "E": 5}

    elements = {
        element["id"]: element
        for element in model.get("elements", [])
        if "id" in element
    }

    flows = {
        flow["id"]: flow
        for flow in model.get("flows", [])
        if "id" in flow
    }

    in_scope = set(crossing_flows(model))

    for flow_id in list(in_scope):
        flow = flows[flow_id]
        in_scope.add(flow["source"])
        in_scope.add(flow["target"])

    recorded = {
        (threat.get("target"), threat.get("category"))
        for threat in model.get("threats", [])
    }

    gaps = []

    for ref in in_scope:
        if ref in elements:
            element = elements[ref]
            categories = applicable(
                element.get("kind", ""),
                is_log=element.get("is_log", False),
            )
        else:
            categories = applicable("data_flow")

        for category in categories:
            if (ref, category) not in recorded:
                gaps.append(Gap(ref=ref, category=category))

    return sorted(gaps, key=lambda gap: (gap.ref, stride_order[gap.category]))

def policy_findings(model: dict) -> list[Issue]:
    findings = set()

    elements = {
        element["id"]: element
        for element in model.get("elements", [])
        if "id" in element
    }

    zones = {
        zone["id"]: zone
        for zone in model.get("zones", [])
        if "id" in zone
    }

    encrypted_protocols = {"https", "tls", "mtls", "sftp", "ssh"}
    crossing = set(crossing_flows(model))

    for flow in model.get("flows", []):
        flow_id = flow.get("id", "")

        if flow_id not in crossing:
            continue

        protocol = flow.get("protocol", "")

        if (
            not isinstance(protocol, str)
            or protocol.lower() not in encrypted_protocols
        ):
            findings.add(
                Issue(flow_id, "UNENCRYPTED_CROSSING")
            )

        source = elements.get(flow.get("source"))
        target = elements.get(flow.get("target"))

        if source is None or target is None:
            continue

        source_zone = zones.get(source.get("zone"))
        target_zone = zones.get(target.get("zone"))

        if source_zone is None or target_zone is None:
            continue

        if (
            target_zone.get("trust", 0)
            > source_zone.get("trust", 0)
            and flow.get("authenticated") is not True
        ):
            findings.add(
                Issue(flow_id, "UNAUTHENTICATED_INBOUND")
            )

    for element in model.get("elements", []):
        if (
            element.get("kind") == "data_store"
            and element.get("holds_pii") is True
        ):
            element_id = element.get("id", "")

            has_disclosure_threat = any(
                threat.get("target") == element_id
                and threat.get("category") == "I"
                for threat in model.get("threats", [])
            )

            if not has_disclosure_threat:
                findings.add(
                    Issue(
                        element_id,
                        "PII_STORE_WITHOUT_I_THREAT",
                    )
                )

    return sorted(
        findings,
        key=lambda issue: (issue.ref, issue.code),
    )


def rank(model: dict) -> list[RankedThreat]:
    ranked = []

    for threat in model.get("threats", []):
        if threat.get("status") != "open":
            continue

        likelihood = threat.get("likelihood")
        impact = threat.get("impact")

        if (
            type(likelihood) is not int
            or not 1 <= likelihood <= 5
            or type(impact) is not int
            or not 1 <= impact <= 5
        ):
            continue

        score = likelihood * impact

        if score >= 15:
            level = "high"
        elif score >= 8:
            level = "medium"
        else:
            level = "low"

        ranked.append(
            RankedThreat(
                id=threat["id"],
                score=score,
                level=level,
            )
        )

    def natural_id(threat):
        import re
        parts = re.split(r"(\d+)", threat.id)
        return [
            (1, int(part)) if part.isdigit() else (0, part.lower())
            for part in parts
        ]

    return sorted(
        ranked,
        key=lambda threat: (
            -threat.score,
            -next(
                item["impact"]
                for item in model["threats"]
                if item["id"] == threat.id
            ),
            natural_id(threat),
        ),
    )

