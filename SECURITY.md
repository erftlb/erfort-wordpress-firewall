# Security policy

Erfort is a security plugin, so a bug here can weaken the site it is meant to
protect. Reports are genuinely welcome.

## Supported versions

Only the latest release is supported. This is a small project maintained by one
studio, so there are no long-term support branches and no backported fixes. If
you are running an older copy, update before reporting.

| Version | Supported |
|---|---|
| latest release | yes |
| anything older | no, please update first |

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting, which is enabled on this
repository: go to the **Security** tab and choose **Report a vulnerability**.
That keeps the report private between you and the maintainer until a fix ships.

If you would rather use email, write to **info@erf.studio** with "Erfort
security" in the subject.

Useful things to include, as far as you have them: the plugin version, the
WordPress and PHP versions, which module is involved (login guard, probe block,
two-factor, integrity, malware scan, hardening, updater), and the smallest set
of steps that reproduces the behaviour.

## What to expect

- An acknowledgement within a few days. This is not a 24/7 operation, and it is
  better to say that plainly than to promise a response time nobody is on call
  to meet.
- An honest assessment of whether the report is something this plugin should
  defend against. Erfort has a deliberately narrow threat model (see the
  docblock at the top of `erf-shield.php`): bot login stuffing, scanners probing
  known paths, user enumeration, XML-RPC amplification. It is not a WAF and does
  not claim to stop a targeted attacker.
- Credit in the release notes if you want it, or none if you prefer.

## Things that are working as intended, not vulnerabilities

Reporting these is fine, but here is the reasoning up front so you can decide
whether it is worth your time:

- **The plugin makes an outbound request.** By default it checks
  `updates.erf.studio` for updates and can auto-apply them. This is documented
  in the README, and there are three ways to turn it off or repoint it.
- **The malware scan is heuristic and report-only.** It flags rather than
  deletes, and it will produce false positives. Quarantine moves a file, it
  never deletes one.
- **Break glass exists.** `wp erfort off` and the `ERF_SHIELD_OFF` constant
  intentionally stand the lockout protections down, because being permanently
  locked out of your own site is also a security failure. Both require access
  you would need anyway (shell, or the ability to edit `wp-config.php`).
- **Internal names still say `erf_shield_`.** The plugin was renamed to Erfort
  publicly; the function prefix and file names were deliberately left alone.
  Cosmetic, not a flaw.
