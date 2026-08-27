# Product Plan

This is a living plan for ideas about what Community Security Agent should
become. Contributors are welcome to add one short idea from their own
perspective. A complete design is not required.

## Add an idea

Copy this format under **Ideas to shape** and open a pull request:

```markdown
### Short idea title

**Perspective:** Who would benefit?

**Today:** What happens now?

**Ideally:** What should be possible?

**Why it matters:** Why is this valuable?
```

Ideas are proposals, not commitments. After review, an idea can move to
**Agreed direction** with a short description of what success looks like.

## What works today

- Extract IoCs from uploaded or pasted security reports.
- Store incidents and sensitivity audit records locally.
- Visualise incident-to-IoC relationships.
- Share findings through Discourse or a labelled local mock.

## Ideas to shape

### Prioritise what matters to one organisation

**Perspective:** Security operator

**Today:** Findings are collected without enough organisation context.

**Ideally:** Match findings to assets, configuration, and controls, then explain
what to act on first and what can be downgraded.

**Why it matters:** Teams cannot investigate every incoming finding.

### Turn raw reports into usable assessments

**Perspective:** Security assessor

**Today:** Some software and reports have no usable severity or remediation
assessment.

**Ideally:** Draft a contextual assessment with severity, remediation,
confidence, and a clear human verification step.

**Why it matters:** Valuable reports otherwise remain difficult to act on.

### Strengthen the ecosystem feedback loop

**Perspective:** Community contributor

**Today:** Findings can be shared, but provenance, review, and reuse need a
clearer workflow.

**Ideally:** Let organisations and experts share traceable findings and
assessments that improve later matching and evaluation.

**Why it matters:** Shared evidence becomes more useful when others can verify
and reuse it.

## Agreed direction

Move reviewed ideas here when they are ready to guide implementation. Include a
brief statement of what success looks like and link any related issue or pull
request.
