# Config corpus

How many real-world nginx configurations ruxen loads. This is one of the four numbers in `ROADMAP.md` ("How progress is measured"), and the list of what blocks the rest is the best guide to what to build next. Issue #216.

```sh
scripts/corpus.py build-nginx      # once: the control nginx, into ~/.cache/ruxen-corpus
cargo build --release
scripts/corpus.py run              # writes corpus/RESULTS.md
scripts/corpus.py run --only gh: -v  # a subset, with a line per case
```

## What's in it

- `sources.tsv`: curated configurations from application documentation and projects (Nextcloud, GitLab, Mastodon, Sentry, Synapse, Vaultwarden, Grafana, …). Each is a file, a Markdown page (every nginx block is a case) or a pinned git repository.
- `github.tsv`: a sample of public configurations from GitHub code search, pinned to commits. Regenerate it with `scripts/corpus.py sample-github`.
- `stubs/`: files the configurations reference and the corpus can ship: nginx's own `mime.types`, `fastcgi_params` and friends (BSD-licensed, from nginx 1.24.0), and Debian's `proxy_params`. A throw-away certificate and key, DH parameters, a ticket key and an empty `htpasswd` are generated on the first run into `~/.cache/ruxen-corpus/stubs`; they are never committed.

Only URLs are committed. The configurations themselves are fetched at run time into `corpus/.cache/` (ignored by git), because their licences vary.

## How a case is checked

1. **Normalised**, so that the check measures ruxen and not the machine:
   - fragments are wrapped in `events {}` / `http {}` / `server {}`;
   - absolute paths move into a per-case sandbox, with stubs where files are needed;
   - include globs get an empty directory;
   - `load_module` lines are commented out;
   - upstream host names nginx would resolve become `127.0.0.1`;
   - ports below 1024 move to 18000 + port (`nginx -t` binds the listening sockets);
   - `listen … ssl` without a certificate gets the stub one.
2. **Checked** with `nginx -t` (the control) and `ruxen -t`.
   - The control is a current nginx release built with the modules distributions enable (`build-nginx`, see `NGINX_VERSION` in the script), not 1.24: real configurations use newer directives such as `http2 on;`.
3. **Counted** only if nginx accepts it.
   - A case nginx rejects (templates with `${VAR}`, broken samples, non-nginx blocks picked from a page) is listed but doesn't count.
   - For the rest, ruxen's first error is the "blocker" the report groups by.

Loading is the first step. Comparing behaviour (the same requests, the same answers as nginx) can follow for a subset.
