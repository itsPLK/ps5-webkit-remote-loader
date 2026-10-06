#!/usr/bin/env python3
"""Summarise defuse-sweep runs from send.py logs.

Reads one or more captured send.py outputs and prints a line per run:

    <file>  outcome  <detail>

`outcome` is one of:

    exploited     reached "payloads loaded" -- the exploit completed end to end
    escalated     reached root but did not load payloads
    sweep-only    the sweep finished but the run stopped before r/w was
                  established; note this can still mean the sweep defused
                  almost nothing, which is a different situation entirely
    wedged        the log stops mid-run -- the last line names the fault site
    truncated     the log has no recognisable end; probably a cut capture

For `wedged`, the detail is the last `cleanup:` line, which is what actually
locates the fault. For `complete`, it is the tally the sweep printed.

Exit status is always 0: this is a reporting aid over captured logs, and a
malformed capture should print a diagnosis rather than fail.
"""

import re
import sys

# "cleanup: id 346 (37/54) step 1/5 lookupAioGroup"
RE_STEP = re.compile(r"id (\d+) \((\d+)/(\d+)\) step (\d)/5")
RE_TALLY = re.compile(
    r"aio cleanup (?:complete|INCOMPLETE): ids=(\d+)\s+cleared=(\d+)\s+"
    r"already-clear=(\d+)\s+reclaimed=(\d+)\s+skipped=(\d+)\s+failed=(\d+)"
)
RE_IDS = re.compile(r"armed ids span (\d+)\.\.(\d+)")
RE_TABLE = re.compile(r"aio table (?:settled after \d+ poll\(s\) at|pointer invalid after)")
RE_BEGIN = re.compile(r"defusing (\d+) armed aio group id")
# Any "<tag>: <text>" progress line from the payload. Used to name the last
# thing a run managed to do when it exited cleanly.
RE_STAGE = re.compile(r"^\[\*\] (?:Kernel|OIDS|Cleanup|ARM|Pipes): (.+)$", re.M)
# Per-id outcomes, used to recount independently of the summary line.
RE_OUTCOME = re.compile(
    r"id (\d+) (cleared|reclaimed|skipped \(|FAILED to clear)"
)


def _line_for(lines, match):
    """Return the source line a match came from. A tally is identified by its
    `ids=N` field, which is unique within a single sweep report."""
    needle = f"ids={match.group(1)}"
    for line in lines:
        if needle in line and ("aio cleanup" in line):
            return line
    return ""


def last_stage(lines):
    """Name the last milestone the run reported, so an early wedge still says
    where it got to. Ordered by progress, first match wins from the end."""
    milestones = [
        "checking aio groups",
        "pipes crossed; verifying kernel read",
        "victim: counter self-check ok",
        "fast read and write ready",
        "read and write ready",
        "Starting kernel exploit",
    ]
    for name in reversed(milestones):
        if any(name in line for line in lines):
            return name
    return None


def summarise(path, text):
    lines = text.splitlines()

    steps = [(m.group(1), m.group(2)) for m in map(RE_STEP.search, lines) if m]
    # The sweep can legitimately report more than once: run() sweeps, and if the
    # tally is not clean, rescue() sweeps again and reports a second time. The
    # later line is the authoritative outcome, so take the LAST match rather
    # than the first -- taking the first invents a "complete" from a run whose
    # first pass was INCOMPLETE.
    tallies = [m for m in map(RE_TALLY.search, lines) if m]
    tally = tallies[-1] if tallies else None
    first_incomplete = bool(tallies) and "INCOMPLETE" in _line_for(lines, tallies[0])
    began = next((m for m in map(RE_BEGIN.search, lines) if m), None)

    ids = next((m for m in map(RE_IDS.search, lines) if m), None)
    ids_note = f" ids={ids.group(1)}..{ids.group(2)}" if ids else ""
    if tally:
        ids_note = ""

    # Recount outcomes as a cross-check on the summary the payload printed.
    counts = {}
    for m in map(RE_OUTCOME.search, lines):
        if m:
            key = m.group(2).split(" (")[0]
            counts[key] = counts.get(key, 0) + 1
    recount = ""
    if counts and not tally:
        recount = " [" + " ".join(f"{k}={v}" for k, v in sorted(counts.items())) + "]"

    if tally:
        # A parsed tally is NOT the same as a successful run. `complete` only
        # describes the sweep; whether the exploit went on to escalate and load
        # payloads is a separate fact, and conflating them hides the case where
        # the sweep "succeeded" having defused almost nothing.
        detail = (
            f"cleared={tally.group(2)} already-clear={tally.group(3)} "
            f"reclaimed={tally.group(4)} skipped={tally.group(5)} "
            f"failed={tally.group(6)} of {tally.group(1)}"
        )
        if "payloads loaded" in text:
            return "exploited", detail + " -> payloads loaded"
        if "privileges ready" in text:
            return "escalated", detail + " -> root, no payloads"
        stopped = next(
            (ln for ln in reversed(lines) if "stopped before kernel r/w" in ln), None
        )
        stopped = "stopped before r/w" if stopped else "did not reach r/w"
        # Two tallies means the first pass was not clean and rescue() swept
        # again. That is a retry succeeding, not a failure -- say so, because
        # "stopped before r/w" alone reads like failure.
        if first_incomplete and "already-clear" in detail:
            cleared = int(tally.group(2))
            already = int(tally.group(3))
            if cleared + already >= int(tally.group(1)) and "skipped=0" in detail:
                return (
                    "sweep-retried",
                    f"first pass incomplete, rescue() retry confirmed {already} already clear -> "
                    f"all {tally.group(1)} accounted for",
                )
        return "sweep-only", f"{detail} -> {stopped}"

    if steps:
        last = steps[-1]
        outcome = "wedged"
        detail = f"last: id {last[0]} ({last[1]}) -- see log for its step{recount}"
        return outcome, detail

    if began:
        return "wedged", "sweep began but no per-id step line was captured"

    if RE_TABLE.search(text) or ids:
        return "wedged", "reached cleanup but stopped before the sweep"

    # A run that reaches the end of the payload exited cleanly, whatever it did
    # or did not sweep. This has to be checked BEFORE the wedge heuristics:
    # with stopAfterArming on, a run never reaches "fast read and write ready"
    # and never sweeps, so every clean exit was being reported as "wedged".
    if "payload done" in text:
        return "exited", summarise_exit(lines)

    # A wedge and a truncated capture are genuinely indistinguishable from the
    # text alone -- both just stop. So report how far the run got, which is the
    # part that narrows it down either way.
    stage = last_stage(lines)
    if stage:
        return "wedged", f"no sweep; stopped after: {stage}"
    return "truncated", "no recognisable end -- capture may be cut short"


def summarise_exit(lines):
    """For a run that reached `payload done`: say what it managed to do.

    `clean exit` here only means the process survived. Whether the console then
    shut down is not visible in the payload log at all -- that has to come from
    the user or from a klog.
    """
    reached = [m.group(1) for m in map(RE_STAGE.search, lines) if m]
    if not reached:
        return "process exited cleanly (nothing reached to report)"
    return (
        f"process exited cleanly; last logged step: {reached[-1]} "
        "-- console behaviour not visible here"
    )


def main(argv):
    if len(argv) > 1 and argv[1] == "-":
        text = sys.stdin.read()
        outcome, detail = summarise("<stdin>", text)
        print(f"<stdin>  {outcome}  {detail}")
        return 0

    rc = 0
    for path in argv[1:]:
        try:
            with open(path, "r", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            print(f"{path}  unreadable  {exc}")
            rc = 1
            continue
        outcome, detail = summarise(path, text)
        print(f"{path}  {outcome}  {detail}")
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))