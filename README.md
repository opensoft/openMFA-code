# openMFA-code

Candidate runtime work is described in [runtime-candidate.md](docs/runtime-candidate.md).
It remains under review and is not an accepted runtime release.

The **code leg** of the `openmfa` project: the implementation and its
tests. The requirements it implements live in
[`opensoft/openMFA-spec`](https://github.com/opensoft/openMFA-spec).

**Clone the assembly root, not this repository.** This leg is mounted as a
submodule at `code/` inside
[`opensoft/openMFA`](https://github.com/opensoft/openMFA), which
is what pins the commit of this repository that the project currently is:

```sh
git clone --recurse-submodules https://github.com/opensoft/openMFA.git
cd openMFA
make bootstrap
```

Working here directly is fine — it is an ordinary repository with an ordinary
branch. What advancing this leg does NOT do is advance the project: that is a
commit in the assembly root moving the gitlink, `contracts/code-pin.yaml` and
any workflow `@<sha>` reference together.

Being the code leg confers no authority over the implementation. The split is
navigation; authority travels in grants, and a project that keeps spec and
code in one repository is reviewed identically.

Topic: `xf-project-openmfa`.

## Product status

The verifier design is captured in the spec leg's wallet-mfa brainstorm packet.
Implementation, published APIs, and deployment await governed acceptance.

## License

[Apache License 2.0](LICENSE).
