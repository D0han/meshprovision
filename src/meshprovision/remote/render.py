"""The text report and the ``--json`` document of a remote diff dry run.

Pure: it returns strings and plain data; the caller prints them (through ``terminal_safe``
and ``echo_json``, which escape control characters in database-recorded text).
"""

from __future__ import annotations

from typing import Final

from meshprovision.remote.ledger import WINDOW_SECONDS, Ledger
from meshprovision.remote.plan import (
    PATH_CAD_SYMBOLS,
)
from meshprovision.remote.plan_types import (
    DryRunPlan,
    Estimate,
    Finding,
    LinkTiming,
    Request,
    Verdict,
)

__all__ = ["ESTIMATE_LINE", "plan_to_json", "render_text"]

ESTIMATE_LINE: Final[str] = (
    "A planning estimate from worst-case arithmetic calibrated in a simulator, not a measurement."
)

_ALLOWED_LINE: Final[str] = (
    "Verdict: allowed offline (every rule this version can check passes; this version "
    "cannot run the read)"
)

_JSON_DECIMALS: Final[int] = 3


def _findings(title: str, findings: tuple[Finding, ...]) -> list[str]:
    if not findings:
        return []
    return [title, *(f"  {finding.code.value}: {finding.message}" for finding in findings)]


def _firmware(plan: DryRunPlan) -> str:
    recorded = plan.firmware_recorded
    if plan.firmware_version is None:
        return f"unknown (recorded {recorded})" if recorded else "unknown (none recorded)"
    dotted = ".".join(map(str, plan.firmware_version))
    return dotted if recorded == dotted else f"{dotted} (recorded {recorded})"


def _gateway(plan: DryRunPlan) -> str:
    if plan.gateway is None:
        return "Gateway: not given"
    authorization = plan.gateway_authorization.value.replace("_", " ")
    return (
        f"Gateway: {plan.gateway}, {authorization}, "
        f"{plan.gateway_attempts} transmissions per unanswered request"
    )


def _request_line(request: Request) -> str:
    size = "measured" if request.measured else "maximum"
    return f"  {request.section:<22}{request.reply_bytes:>4} B {size}"


def _timing_line(timing: LinkTiming) -> str:
    links = f"{timing.links} link{'' if timing.links == 1 else 's'}"
    return (
        f"  {links}: {timing.deadline_typical:.1f} s / {timing.deadline_worst_case:.1f} s, "
        f"run {timing.longest_run_typical:.0f} s / {timing.longest_run_worst_case:.0f} s"
    )


def _share(ledger: Ledger) -> str:
    if not ledger.fits:
        return "does not fit"
    count = ledger.per_window
    return f"fits {count} time{'' if count == 1 else 's'} per rolling hour"


def _estimate_lines(estimate: Estimate) -> list[str]:
    e = estimate
    t, w = e.ledger, e.ledger_worst_case
    settle = f"settle {e.settle.min_seconds:g}-{e.settle.max_seconds:g} s"
    lines = [
        f"Radio: {e.region} {e.preset}, slot {e.slot_ms} ms ({PATH_CAD_SYMBOLS} CAD symbols "
        f"assumed), {settle}",
        f"Deadline per request, and the longest run if every request ran to it "
        f"(CW {t.cw} / CW {w.cw}):",
        *(_timing_line(timing) for timing in e.timings),
        f"Airtime in one rolling hour, CW {t.cw} / CW {w.cw} (spurious retransmits "
        f"x{t.spurious_factor:.3f} / x{w.spurious_factor:.3f}):",
        f"  gateway      {t.gateway_seconds:.2f} s / {w.gateway_seconds:.2f} s "
        f"({t.gateway_unanswered_seconds:.2f} s if no request is answered)",
        f"  each relay   {t.relay_seconds:.2f} s / {w.relay_seconds:.2f} s "
        f"({t.relay_largest_replies_seconds:.2f} s / {w.relay_largest_replies_seconds:.2f} s "
        "at the largest replies)",
        f"  destination  {t.destination_seconds:.2f} s / {w.destination_seconds:.2f} s",
    ]
    if t.budget_seconds is None:
        lines.append("  polite share none (the region has no duty-cycle limit)")
    else:
        lines.append(
            f"  polite share {t.budget_seconds:.2f} s per relay: {_share(t)} at CW {t.cw}; "
            f"{_share(w)} at CW {w.cw}"
        )
    return lines


def render_text(plan: DryRunPlan) -> str:
    """Return the report as text, without a trailing newline.

    Args:
        plan: The plan to report.

    Returns:
        The lines joined with newlines.
    """
    kind = "full diff" if plan.full_diff else "--section"
    lines = [
        f"Remote diff dry run for {plan.destination}: nothing was sent and no radio was contacted.",
        ESTIMATE_LINE,
        "",
        _ALLOWED_LINE if plan.verdict is Verdict.ALLOWED else "Verdict: refused",
        *_findings("Refused:", plan.refusals),
        *_findings("Notes:", plan.notes),
        f"Destination: {plan.destination}, firmware {_firmware(plan)}",
        _gateway(plan),
        f"Requests ({len(plan.requests)}, {kind}):",
        *(_request_line(request) for request in plan.requests),
    ]
    if plan.estimate is None:
        lines.append("No airtime estimate: the region or the preset is outside the model.")
    else:
        lines.extend(_estimate_lines(plan.estimate))
    return "\n".join(lines)


def _rounded(value: float) -> float:
    return round(value, _JSON_DECIMALS)


def _ledger_json(ledger: Ledger) -> dict[str, object]:
    budget = ledger.budget_seconds
    return {
        "cw": ledger.cw,
        "window_seconds": WINDOW_SECONDS,
        "budget_seconds": None if budget is None else _rounded(budget),
        "spurious_factor": _rounded(ledger.spurious_factor),
        "gateway_seconds": _rounded(ledger.gateway_seconds),
        "gateway_unanswered_seconds": _rounded(ledger.gateway_unanswered_seconds),
        "relay_seconds": _rounded(ledger.relay_seconds),
        "relay_largest_replies_seconds": _rounded(ledger.relay_largest_replies_seconds),
        "destination_seconds": _rounded(ledger.destination_seconds),
        "fits": ledger.fits,
        "per_window": ledger.per_window,
    }


def _estimate_json(estimate: Estimate) -> dict[str, object]:
    settle = estimate.settle
    return {
        "region": estimate.region,
        "preset": estimate.preset,
        "slot_ms": estimate.slot_ms,
        "cad_symbols": PATH_CAD_SYMBOLS,
        "settle": {
            "quiet_seconds": _rounded(settle.quiet_seconds),
            "min_seconds": _rounded(settle.min_seconds),
            "max_seconds": _rounded(settle.max_seconds),
        },
        "timings": [
            {
                "links": timing.links,
                "deadline_typical": _rounded(timing.deadline_typical),
                "deadline_worst_case": _rounded(timing.deadline_worst_case),
                "longest_run_typical": _rounded(timing.longest_run_typical),
                "longest_run_worst_case": _rounded(timing.longest_run_worst_case),
            }
            for timing in estimate.timings
        ],
        "ledger": _ledger_json(estimate.ledger),
        "ledger_worst_case": _ledger_json(estimate.ledger_worst_case),
    }


def _finding_json(finding: Finding) -> dict[str, str]:
    return {"code": finding.code.value, "message": finding.message}


def plan_to_json(plan: DryRunPlan) -> dict[str, object]:
    """Return the ``--json`` document: plain data, floats rounded to 3 decimals, no key bytes.

    Args:
        plan: The plan to report.

    Returns:
        The document, ready for ``json.dumps``.
    """
    reading = plan.air_util_tx
    return {
        "dry_run": True,
        "node": plan.destination,
        "verdict": plan.verdict.value,
        "refusals": [_finding_json(finding) for finding in plan.refusals],
        "notes": [_finding_json(finding) for finding in plan.notes],
        "full_diff": plan.full_diff,
        "firmware": {
            "recorded": plan.firmware_recorded,
            "version": (
                None if plan.firmware_version is None else ".".join(map(str, plan.firmware_version))
            ),
            "security_read": plan.security_read,
        },
        "gateway": {
            "node": plan.gateway,
            "authorization": plan.gateway_authorization.value,
            "unanswered_attempts": plan.gateway_attempts,
        },
        "destination_air_util_tx": (
            None
            if reading is None
            else {
                "percent": _rounded(reading.percent),
                "age_seconds": _rounded(reading.age_seconds),
            }
        ),
        "requests": [
            {
                "section": request.section,
                "kind": request.kind.value,
                "reply_bytes": request.reply_bytes,
                "reply_size": "measured" if request.measured else "maximum",
            }
            for request in plan.requests
        ],
        "estimate": None if plan.estimate is None else _estimate_json(plan.estimate),
    }
