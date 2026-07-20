# wp2shell-poc

Independent proof-of-concept for the unauthenticated WordPress REST batch route-confusion
SQL injection associated with Searchlight Cyber's wp2shell advisory.

This repository is not Searchlight Cyber's official checker. `PoC.py` can probe the vulnerable
route with `--check`, demonstrate database reads with `--read` or `--dump-users`, and run commands
with supplied administrator credentials or by first exercising the SQLi-to-admin bridge.

![wp2shell — the `shell` command exercising the pre-auth SQLi-to-admin bridge](docs/shell.svg)

## Affected versions

Searchlight Cyber's advisory lists these wp2shell RCE exposure ranges:

| Version range | Status |
| ------------- | ------ |
| <= 6.8.5 | Not affected |
| 6.9.0 – 6.9.4 | Affected |
| 7.0.0 – 7.0.1 | Affected |

## How it works

The REST batch endpoint (`/batch/v1`) is unauthenticated and runs several sub-requests in one
call, relying on each sub-request being validated and permission-checked on its own.

`serve_batch_request_v1()` builds two parallel arrays — `$matches` (the matched handler per
sub-request) and `$validation` (the validation result per sub-request) — then indexes both by
the same offset when dispatching. A sub-request whose path fails `wp_parse_url()` is appended to
`$validation` but not to `$matches`, so the arrays fall out of step and a sub-request is
dispatched under a **different** sub-request's handler. That is the route confusion.

The PoC nests the primitive twice:

1. A `POST /wp/v2/posts` request that carries a `requests` body is dispatched under the batch
   handler itself. Having been validated as a posts request, its `requests` list is never checked
   against the batch schema, so its sub-requests may use `GET` — the method allow-list is
   bypassed.
2. Inside that inner batch, a `GET /wp/v2/posts/999999` item-route request carries posts collection
   query params such as `author_exclude`, `orderby`, and `per_page`. The `999999` ID does not need
   to exist; it is just an unlikely post ID used to match the item route, whose schema does not
   validate those collection-only params. The desync then dispatches the same request under posts
   `get_items()`, where `author_exclude` maps to the `WP_Query` `author__not_in` query var, which
   the vulnerable build interpolates into SQL as a string.

The result is a boolean- and time-based blind SQL injection reachable pre-authentication. This PoC
also includes the UNION fake-post primitive used by the SQLi-to-admin chain.

The RCE path implemented here is:

1. Use UNION fake `wp_posts` rows to render attacker-controlled content through a posts collection.
   The render bridge uses the `/wp/v2/posts/999999` item-route source — the same route the SQLi read
   uses to reach `get_items()`.
2. Use that render to make WordPress create real oEmbed cache posts.
3. Recover those real cache post IDs through the SQLi.
4. In one poisoned batch request, recast those IDs as a customizer changeset, navigation item, and
   request hook shape.
5. Let the same request reach `POST /wp/v2/users`, creating a generated administrator.
6. Log in as that generated administrator and use the theme editor to deploy a command shell.

Steps 1–5 are pre-authentication; the command-execution step requires the generated or supplied
administrator account.

## Requirements

Python 3.8+ and the standard library. No third-party dependencies.

## Usage

Run `PoC.py` from the repository directory. Use `python3` instead of `python` when that is how
Python 3 is installed on your system.

```
python PoC.py (--url URL | --file FILE) [--check | --read SQL | --dump-users | --cmd CMD | --shell] [options]
```

Use `--url` for one target or `--file` for a text file containing one target URL per line. For
multi-target runs, `--threads` controls concurrency and defaults to 100.

### Check — non-destructive route-confusion probe

`--check` sends the batch marker probe and stops before SQL injection or command execution. A
vulnerable batch implementation returns the route-confusion marker pattern `parse_path_failed`,
`block_cannot_read`, and `rest_batch_not_allowed`.

The marker probe is based on the WordPress core fix. The malformed `///` request creates
`parse_path_failed`; a `/wp/v2/posts` request acts as a batch-allowed spacer; the
`/wp/v2/block-renderer/...` route is not batch-allowed but returns `block_cannot_read` if its
handler is reached anonymously; `/batch/v1` gives `rest_batch_not_allowed`. On vulnerable builds
the parse error shifts the batch handler arrays out of step, so the spacer request is dispatched
under the block-renderer handler. Fixed builds keep the arrays aligned, so this exact all-three
pattern should not appear for the crafted probe.

```
python PoC.py --url http://target --check
python PoC.py --url http://target --check --output vulnerable.txt
python PoC.py --file targets.txt --threads 100 --check --output vulnerable.txt
```

### Read — extract data through SQL injection

```
python PoC.py --url http://target --read "SELECT @@version"
python PoC.py --url http://target --read "SELECT DATABASE()"
python PoC.py --url http://target --dump-users
python PoC.py --file targets.txt --threads 50 --read "SELECT @@version" --output readable.txt
```

Both read modes require the UNION-based extraction path. `--read` evaluates one scalar SQL
expression, while `--dump-users` reads IDs, usernames, and password hashes from `wp_users`.
`--output` appends successful target URLs to a file; it does not save the extracted value or user
records.

### Command execution

With both `--user` and `--password`, `PoC.py` logs in with the supplied administrator credentials.
Without credentials, it first attempts the pre-auth SQLi-to-admin bridge and then logs in as the
generated administrator.

Use `--cmd` to run one command or `--shell` for the interactive mode. Interactive mode is limited
to a single target and cannot be combined with `--file`.

```
python PoC.py --url http://target --user admin --password "<password>" --cmd "id"
python PoC.py --url http://target --user admin --password "<password>" --shell
python PoC.py --url http://target --cmd "id"
python PoC.py --url http://target --shell
python PoC.py --file targets.txt --threads 50 --cmd "id" --output exploited.txt
```

The command-execution path writes a token-protected shell through the WordPress theme editor and
prints its URL. Unless `--no-cleanup` is used, `PoC.py` attempts cleanup after execution, including
removing an administrator created by the pre-auth bridge.

## Options

| Option | Applies to | Description |
| ------ | ---------- | ----------- |
| `--url URL` | target | Test one WordPress base URL. |
| `--file FILE` | target | Read target URLs from a file, one URL per line. |
| `--threads N` | file mode | Concurrent workers (default: 100). |
| `--proxy URL` | all | Route traffic through an HTTP proxy, for example Burp. |
| `--timeout N` | all | Request timeout in seconds (default: 30). |
| `--check` | check | Run only the non-destructive route-confusion marker probe. |
| `--read SQL` | read | Read one scalar SQL expression through UNION SQL injection. |
| `--dump-users` | read | Dump IDs, usernames, and password hashes from `wp_users`. |
| `--cmd CMD` | execution | Run one command after deploying the shell. |
| `--shell` | execution | Request an interactive shell; single-target mode only. |
| `--user USER` | execution | Administrator username; use together with `--password`. |
| `--password PASSWORD` | execution | Administrator password; use together with `--user`. |
| `--no-cleanup` | execution | Skip cleanup and leave created artifacts on the target. |
| `--output FILE` | all | Append successful or vulnerable target URLs to a file. |

## Remediation

Update to WordPress 7.0.2, or 6.9.5 if the site is on the 6.9 branch. Until then,
block both `/wp-json/batch/v1` and the `rest_route=/batch/v1` query parameter at
the edge, or require authentication for the batch endpoint via the
`rest_pre_dispatch` filter.

## Legal

For authorized security testing only. Use it exclusively against systems you own or have explicit
written permission to test. No warranty is provided and no liability is accepted for misuse.

## References

- WordPress 7.0.2 release announcement — <https://wordpress.org/news/2026/07/wordpress-7-0-2-release/>
- Searchlight Cyber wp2shell advisory — <https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core/>
- sergiointel/wp2shell-poc SQLi-to-admin bridge — <https://github.com/sergiointel/wp2shell-poc>
