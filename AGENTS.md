This is the **code leg** of openMFA (`openmfa`): the implementation
and its tests.

**The project's rules are not here.** They are in the assembly root
`opensoft/openMFA`, in `AGENTS-shape.md` — read that before touching anything
that spans the legs. This leg is mounted there at `code/`, and the other leg,
`opensoft/openMFA-spec`, beside it at `../spec/`, once the root is cloned with
`--recurse-submodules`.

Working here is ordinary — an ordinary repository on an ordinary branch. What
advancing this leg does NOT do is advance the project: that is ONE commit in
`opensoft/openMFA` moving the gitlink, `contracts/code-pin.yaml` and every
workflow `@<sha>` for this leg together.

Being the code leg confers no authority over the implementation. The split is
navigation.

## Candidate runtime gates

Use the assembly root and shared OpenSpec/Speckit protocol. This leg owns the
candidate implementation/tests, while the spec leg owns canonical contracts
and feature files. No gate reads a sibling checkout.

In an isolated environment in the declared development bench, install
`pip install -e . pytest` and run `python -m pytest tests/ -q` from this
leg's root. No live backend, credential or network call is used by the suite.
The state-test factor verifier is an explicit fixture, not real factor
acceptance. Missing production backends must refuse; never add a default
verified flag or an assurance upgrade to clear tests.

No leg is tagged. A consumer accepts an assembly root through reviewed
lockstep pins after the real adapter/custody/compatibility gates pass.
