# Agent planning, review, and delivery workflow

This is permanent repository policy, not a task plan. Read it with the
[engineering preferences](../../AGENTS.md#engineering-preferences),
[validation requirements](../../AGENTS.md#build-and-validation), and
[independent review requirements](../../AGENTS.md#independent-subagent-workflows).

For planned work, follow these stages:

1. **Announce the workflow and commit the plan.**
   - Tell the user the working branch, baseline, plan and review-record paths,
     and intended delivery branch. Explain that review rounds retain the plan
     and fixup history, and delivery preparation requires an explicit request.
     Distinguish **ready for further review** from **ready to merge**; do not
     require the user to read this file to discover the process.
   - Record intent, scope, starting baseline, preserved invariants, owning guides,
     and the difference between current and proposed behavior.
   - Define ordered commit boundaries with stable identifiers, coherent behavior,
     affected consumers, and acceptance evidence. Include applicable tests,
     changes fragments, and permanent documentation with each implementation
     commit. Keep removal with any required replacement or recovery path.
   - Name independent design, intermediate integration, and final integration
     gates. Place intermediate gates at specified commit boundaries based on
     meaningful ownership or architecture changes. State each gate's combined
     scope, required evidence, and exit criteria; scale their number to the work.
     Identify permanent destinations and necessary AGENTS.md links for enduring
     rules rather than deferring documentation to the end.

2. **Pass independent design review before substantive implementation.**
   - At this and every subsequent independent review stage, where possible start
     agents without inherited conversation history. Provide a self-contained
     brief with intent, baseline, scope, invariants, and validation evidence,
     plus access to relevant repository state and Git history.
   - Have a reviewer challenge necessity, scope, security assumptions, and simpler
     alternatives, including cross-component and OOM interactions where relevant.
   - Resolve material design findings before building on the affected decisions.
     Update the committed plan and record the review evidence.

3. **Implement phases with exact-commit and fixup review.**
   - For every implementation review, including integration and delivery
     reviews, have the reviewer record an initial assessment before consulting
     the author's rationale and prior findings, then reconcile it with all prior
     findings and fixups before completing the review.
   - Independently review each exact implementation SHA and its relevant
     consumers. Use `git commit --fixup=<introducing-SHA>` for defects
     introduced by commits in the working branch's own series after the
     recorded baseline. Give fixes to inherited defects standalone commits
     with messages explaining the defect and correction. Independently review
     each fixup and standalone commit; the reviewer must not be its author.
   - Commit findings, causes, resolutions, fixup references, and validation
     evidence in the plan or accompanying review record. Preserve phase commits,
     fixups, and this evolving record so later reviewers can trace what changed
     and why, rather than seeing only the final diff.

4. **Pass the named integration gates, including final integration review.**
   - At each specified boundary, independently review the accumulated
     implementation and complete affected call chains. Include all prior plan
     commits and fixups alongside surrounding code, including previously
     approved code and relevant unchanged high-risk consumers.
   - After recording the initial assessment, explicitly review the aggregate
     findings and fixup history for recurring anti-patterns, repeated
     assumptions, cross-component hazards, and testing gaps. Look for the same
     problems elsewhere in the branch; individual
     fixup approval does not discharge this responsibility.
   - Add regression coverage for gaps exposed by fixes and resolve additional
     findings. Decide whether recurring causes require a wider audit,
     simplification, or design change. Include the
     [complexity review](../../AGENTS.md#build-and-validation) and the handoff
     to permanent documentation in the applicable gates.
   - Record scope, reviewed SHAs, findings, and validation. Exit a gate only when
     material findings are resolved and its acceptance evidence is satisfied;
     record unavailable checks explicitly without treating them as passes.
     Do not build dependent work on unresolved material findings.
   - Material later changes reopen affected gates and require appropriate
     revalidation. Per-commit approvals never replace accumulated review; the
     final integration gate covers the full planned branch and all prior fixups
     before any delivery preparation.
   - At final integration, compare each planned outcome with the delivered
     behavior and its acceptance evidence. Identify missing work and record
     the reasons for deviations before reporting completion.
   - Once the accumulated-fixup review converges, automatically give a fresh
     independent reviewer a plan-free snapshot and the net diff from the
     implementation baseline. A temporary checkout suffices. Verify that its
     tree matches the working revision apart from this task's temporary plan
     and review records. Keep tests, changes fragments, and permanent docs.
   - Have the reviewer trace the final behavior through its callers and cleanup
     paths. Supply intent, constraints, and validation gaps up front. Record
     the initial assessment before consulting the plan rationale or fixup
     history, then reconcile findings as in step 3.
   - Correct actionable findings on the working branch under step 3. Rerun
     affected checks and integration reviews, including accumulated-fixup
     review. Give the updated snapshot to a fresh reviewer and repeat.
   - Stop when the squashed review has no unresolved actionable findings, the
     gate's acceptance evidence is satisfied, and the current implementation
     tree still matches the reviewed snapshot. Record the baseline, reviewed
     working SHA, and excluded paths. A commit that only records the result
     leaves that match intact. Later implementation changes require a fresh pass.

5. **Present the working branch and continue review rounds with the user.**
   - After implementation and planned reviews, present the working branch with
     the committed plan, review record, and unsquashed fixup history intact.
     Invite further review rounds before delivery preparation; record new
     findings, independently review fixes, and repeat affected gates, including
     aggregate fixup review, and validation.
   - At each handoff, report the branch and reviewed SHA (or identified snapshot
     for uncommitted work), whether plan and fixup history remain intact, and
     outstanding findings, validation, or cleanup. Report the outcome of both
     the accumulated-fixup and squashed reviews. When ready, tell the user:
     “Say ‘Prepare the delivery branch’ to have the plan-free commit series
     assembled and independently reviewed against the agreed base.”
   - Do not impose a fixed number of rounds, squash away fixup history while
     keeping only the plan, or treat plan completion as permission to prepare
     delivery.

6. **Prepare a separate delivery branch when explicitly requested.**
   - Announce source and destination branches. Resolve material findings and
     verify permanent documentation first, then create a new delivery branch
     from the agreed delivery base. Record its exact SHA and the working
     branch's implementation baseline.
   - Transfer implementation, regression tests, changes fragments, and permanent
     documentation into coherent commits. Fold reviewed fixups only into
     introducing commits in the delivery series. If the delivery base already
     contains the introducing change, carry any outstanding correction as a
     standalone commit with its own descriptive message. Preserve authorship
     and relevant attribution.
   - Exclude temporary plan and review artifacts from every new delivery commit
     and its ancestry. Do not merge the working branch into it. Reconstruct mixed
     plan/code patches without temporary material; deleting that material in
     the last commit does not remove its history.
   - Keep the original working branch, plan, review record, and unsquashed history
     available after preparation. Do not rewrite or delete them as routine
     cleanup. Other plan-storage or history-rewriting workflows are exceptions
     only when explicitly requested by the user, not routine choices.

7. **Review and report the prepared delivery branch.**
   - Inspect every new delivery commit and its ancestry for temporary artifacts.
     When both branches start from the same base, verify that their trees
     match after excluding temporary plan and review material.
   - If the agreed delivery base has advanced, compare the working and delivery
     changes against their respective bases, excluding the same temporary
     material. Account for upstream changes, including work already present
     on the delivery base. Identify adaptations for review and rerun the
     affected checks.
   - Have an independent subagent review the prepared delivery branch before
     declaring it merge-ready. Give the reviewer the working and delivery
     branches, both base SHAs, exact delivery SHAs, SHA mapping, and validation
     evidence. After recording the initial assessment, have the reviewer consult
     the plan and reconcile all accumulated findings and fixups. Require review
     of every new exact SHA and the combined branch, including relevant consumers
     and any changes introduced by preparation; the reviewer must not be the
     author.
   - Revalidate changes introduced by preparation. Reuse earlier test evidence
     only where source and build configuration remain equivalent, and keep the
     review-to-delivery SHA mapping outside the merged tree.
   - If substantive findings emerge, carry them back to the working branch's
     review record, fix and review them there, reopen affected gates, and prepare
     and review a new delivery revision.
   - Report both branches and reviewed SHAs, validation carried forward or rerun,
     and remaining findings or cleanup. Preparation does not authorize pushing
     or merging. No completed-plan archive or plan-only commits belong in the
     merged branch.

