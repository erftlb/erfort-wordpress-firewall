# Erfort

A small, honest WordPress firewall. No cloud, no telemetry, no upsells, no
"military grade" marketing - just the deterministic protections that actually
matter for a portfolio, nonprofit, or small-business site on shared hosting.

Built and maintained by [Erf Studio](https://erf.studio).

## Why this exists

Most WordPress security plugins are built for the wrong threat model: a
targeted, sophisticated attacker. That's not what actually arrives at a small
site. What arrives is bot login stuffing, scanners probing known plugin
holes, user enumeration to feed the stuffing, and XML-RPC amplification.
Erfort protects against exactly that, and nothing more - no regex WAF, no
signature scanner, no "score" to chase. Every protection here is cheap,
deterministic, and safe to leave on.

## What it does

- **Login guard** - five failed attempts in fifteen minutes locks that IP
  *and* that username out for fifteen minutes. Login errors are generic
  ("the credentials do not match"), so the form never confirms which
  usernames exist.
- **Probe block** - a fixed list of scanner paths (`.env`, `wp-config`
  backups, `.git/`, Adminer, `phpunit`, and friends) answers 403 before
  WordPress even builds a query for it.
- **XML-RPC off** - the whole legacy endpoint is blocked, pingbacks
  included.
- **Enumeration off** - no `?author=` username leaks, no anonymous REST
  user list.
- **Security headers** - the boring, correct ones: `X-Frame-Options`,
  `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`.
- **File editors off** - the wp-admin theme/plugin editors are removed
  (updates still work fine).
- **Version cloak** - no WordPress generator tag in the page head.
- **Two-factor authentication** - TOTP (Google Authenticator-compatible),
  with an optional grace-period policy that requires admins to enrol.
- **Core & plugin integrity checks** - compares installed files against
  official WordPress.org checksums.
- **Malware scan** - a deterministic signature scan of `wp-content` and
  PHP-in-uploads. Report-only by default; an optional one-click quarantine
  moves a flagged file to a locked folder (never auto-deletes).
- **Weekly health digest** - one email: pending updates, latest scan
  results, admin count, event volume. Off by default.
- **A plain event log** - the only record kept, visible in one screen.

## Install

Download this repository and copy it into `wp-content/plugins/erfort/`,
then activate. That's the whole install - no build step, no configuration
required to get useful protection immediately. (The plugin's internal file
is still named `erf-shield.php` - that's the original code prefix, not a
leftover mistake; see the docblock at the top of that file for why it
stayed unchanged when the plugin was publicly renamed to Erfort.)

## Philosophy

- No cloud, nothing phones home by default.
- No dashboards, no scores, no upsells.
- Report-only where a wrong call could lock someone out or delete something
  real - quarantine over delete, and a "break glass" mode
  (`wp erfort off`) to disable lockout protections if you ever lock
  yourself out.
- Ships off/safe by default. Every optional feature is opt-in.

## Self-hosted updates

As shipped, this copy checks `updates.erf.studio` (the author's own manifest)
roughly every 6 hours and **auto-updates itself in the background** when a
new version is published there - the same "official builds, no
wordpress.org gatekeeping" pattern the self-hosted manifest exists for.
Be aware of what that means before you deploy this: your site will pull and
apply whatever the author publishes to that URL, unattended.

Three ways to change that:
- **Opt out of auto-update only** (still checks for updates, shows them in
  the Plugins screen, just never applies one without a click): add
  `define( 'ERF_UPDATER_NO_AUTO', true );` to `wp-config.php`.
- **Point it at your own manifest instead**: edit the `manifest` URL at the
  bottom of `includes/updater.php` to your own hosted JSON (same shape,
  see that file's docblock).
- **Remove it entirely**: delete `includes/updater.php` and its line in the
  module-loader array near the top of `erf-shield.php`. Everything else in
  the plugin is unaffected either way.

## License

MIT - see `LICENSE`. The only real condition: keep the copyright notice
(credit to [Erf Studio](https://erf.studio)) in any copy or fork.
