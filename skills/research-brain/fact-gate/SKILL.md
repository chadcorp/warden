# Fact Gate

Verify every factual, legal, or financial claim against a **dated primary
source** before anything ships. This is a blocking discipline: a draft does not
pass until each checkable claim is signed off.

## When to use
Any deliverable that cites laws, official figures, statistics, regulations,
rates, or deadlines — or whenever someone asks "is this accurate?" / "check this
against sources."

## The protocol

1. **Extract the checkable claims.** Walk the draft and pull out every assertion
   a reader could dispute: numbers, dates, rates, thresholds, named rules,
   jurisdictions. Restate each as a single, testable sentence.

2. **Class each claim.** Tag the kind of claim, because each kind has a typical
   failure mode:
   - *Rate / amount* — often stale; verify the year it applies to.
   - *Threshold / phase-out limit* — easy to off-by-one; confirm the exact band.
   - *Deadline* — confirm the current cycle, not last year's.
   - *Jurisdiction / forum* — confirm the level (federal vs state, court vs
     agency); loose phrasing from a single outlet is a classic trap.

3. **Match each claim to a dated primary source.** Prefer the authoritative
   issuer (the statute, the official table, the regulator's own page) over a
   secondary summary. Record the source and its date next to the claim.

4. **Block on the unverifiable.** If a claim cannot be tied to a primary source,
   it does not ship as fact. Either soften it to attributed opinion ("according
   to X…"), or cut it. Never assert a number you could not source.

5. **Re-read for the silent claim-classes.** Court forum, effective dates,
   "up to" limits, and percentages are the ones a casual pass skips. Sweep for
   them explicitly.

## Output
A claims ledger: each claim, its class, its dated source, and a status of
**SIGNED / SOFTENED / CUT**. The draft passes only when no claim is left
unsigned. If anything is post-dated beyond your knowledge or unsourced, say so
plainly rather than guessing.

## Honesty rule
"I could not verify this" is a valid, valuable result. A fact gate that waves
everything through is not a gate.
