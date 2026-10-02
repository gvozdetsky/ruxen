# Security policy

ruxen is an experimental prototype and is not meant for production yet (see the
README). Security reports are still very welcome: a bug that would matter in
nginx most likely matters here too, and finding it early is the point.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through GitHub:
**[Report a vulnerability](https://github.com/gvozdetsky/ruxen/security/advisories/new)**
(the repository's *Security* tab → *Report a vulnerability*).

Useful to include:

- the ruxen version or commit (`ruxen -V`);
- a minimal configuration and the request(s) that trigger it;
- what happens, and what nginx 1.24 does with the same configuration if you
  checked.

ruxen is maintained by one person, so replies are best effort. You will get an
answer in the advisory thread, and the fix is discussed there before anything
is public.

## What counts

Anything a client, an upstream server or a configuration can use to make ruxen
do something it shouldn't, for example:

- request smuggling, response splitting, header injection;
- reading files outside `root` / `alias`, or bypassing `auth_basic`;
- a crash, hang or unbounded memory/CPU use triggered by a request or by an
  upstream response;
- a directive that ruxen accepts but silently doesn't enforce, when it restricts
  access (ruxen refuses such configurations on purpose; a gap there is a bug).

Missing nginx features and behaviour differences that aren't security-relevant
are ordinary issues: use the *nginx behaviour difference* template.

## Supported versions

Fixes go into the latest release only (currently `0.1.x`).

## Disclosure

Once a fix is released, the advisory is published and the release notes have a
*Security* section describing the problem and the affected versions. Reporters
are credited unless they prefer not to be.
