# Security policy

## Supported versions

kshield has no stable release yet. Security fixes go to the `main` branch and to the latest release.

## Report a vulnerability

Do not open a public issue for a security problem.

Use GitHub private vulnerability reporting: open the **Security** tab of this repository and click **Report a vulnerability**.

Please include:

- the kshield version (`kshield version`) or commit,
- the command you ran and a minimal input that shows the problem,
- what you expected and what happened,
- the impact as you see it.

You get a first answer within 7 days. When the fix is ready, the advisory is published with credit to you, unless you ask not to be named.

## Scope

In scope:

- a wrong verdict that hides a real risk (a false PASS),
- a report or evidence pack that leaks a Secret value,
- `kshield evidence verify` accepting a changed or unsigned pack,
- `kshield scan cluster` sending any request other than read requests, except the pods of `--node-probe`,
- generated remediation policies that are weaker than the documentation says.

Out of scope: findings in the test fixtures under `test/`, which are insecure on purpose.
