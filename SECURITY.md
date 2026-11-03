<!-- Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE. -->
# Security policy

## Reporting a vulnerability

Please report security problems privately, not in a public issue or pull request.

Use GitHub's private vulnerability reporting: on the repository's **Security** tab,
choose **Report a vulnerability**, or go to
https://github.com/stevenfoong/my-bastion/security/advisories/new

Include what you found, the version (`mybastion --version` or `dpkg -l mybastion`),
and how to reproduce it if you can. A proposed fix is welcome but not needed.

We'll acknowledge the report, keep it private while we fix it, and credit you in
the release notes unless you'd rather not be named. Please give us a chance to
release a fix before publishing details.

## Supported versions

Security fixes go into the latest release. Please upgrade to it before reporting,
and check the [releases](https://github.com/stevenfoong/my-bastion/releases) for whether
a problem is already fixed.

## Scope

My Bastion itself: the web server, its API, the session client pages, and the
packaging in this repository (including the bundled, patched guacd build).
Problems in upstream projects (Apache Guacamole's guacd, FreeRDP, Vault or
OpenBao) are best reported to them, but tell us too if My Bastion is affected.

See [docs/security.md](docs/security.md) for how My Bastion is hardened.
