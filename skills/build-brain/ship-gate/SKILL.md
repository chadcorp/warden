# Ship Gate

An **independent** GO/NO-GO release gate. It runs cold on a finished
deliverable, trusts no claim from the build log, and blocks on a small set of
unwaivable conditions. Its job is to catch the thing the builder, tired and
close to the work, can no longer see.

## When to use
"Is it ready to ship?", "Gate this", "Final check before publishing", or before
anything goes out the door.

## The protocol

1. **Forget the build story.** Read only the artifacts. The build log's "it
   works" is hearsay; the gate re-derives the truth from the deliverable itself.

2. **Re-derive the numbers.** Take the headline figures and recompute them a
   second, independent way from the raw inputs. If a total does not reconcile,
   that is a blocking NO-GO.

3. **Re-check the facts.** Every cited figure, date, rate, or rule must trace to
   a dated primary source (delegate to `research-brain/fact-gate`). An unsourced
   factual claim is a NO-GO.

4. **Confirm the files.** The artifacts named in the deliverable must exist,
   open, and contain what the listing says. A promised file that is missing or
   empty is a NO-GO.

5. **Check the empty and edge states.** Open the product with no data and with
   extreme data. A view that breaks or shows a wrong value is a NO-GO.

6. **Screen for policy and honesty.** No claim you cannot stand behind, no
   "100% guaranteed," no figure you could not reproduce. Honesty is a gate
   condition, not a nicety.

## The unwaivable conditions (any one ⇒ NO-GO)
- A headline number that does not reconcile a second way.
- A factual claim with no dated primary source.
- A named artifact that is missing, empty, or unopenable.
- A broken empty/edge state.
- A claim that overstates what the product does.
- A policy violation in the user-facing surface.

## Output
A one-line **GO** or **NO-GO**, then the evidence: what was re-derived, what was
re-checked, and — on NO-GO — the exact blocking condition and how to clear it.

## Honesty rule
A gate that always says GO is decoration. The respectful act is to block a real
problem before a buyer finds it.
