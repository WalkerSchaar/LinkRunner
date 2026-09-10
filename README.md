# LinkRunner

LinkRunner is a Google Drive exposure-auditing tool. Starting from one or
more seed folders/files, it recursively crawls a Drive environment,
resolves shortcuts across drives, flags any resource shared with
**"anyone with the link"** (`type="anyone"`), mines the plain-text content
of Docs/Sheets/Slides/text files for embedded links (in memory only —
nothing is written to disk), and produces a CSV audit report of what it
found, including how deep each resource sits in the crawl tree.

It's an updated, single-file rewrite in the spirit of
[PaperChaser](https://github.com/mandatoryprogrammer/PaperChaser), aimed at
letting you (or your org) find accidental zero-authentication exposure in
your own Drive.

> **Use only against Drive environments you own or are explicitly
> authorized to assess.** LinkRunner only reads permissions and content
> already visible to the authenticated identity via the standard Drive API
> — it does not bypass authentication or exploit anything.

## Features

- **Folder & shortcut traversal** — recursively walks subfolders and
  resolves `application/vnd.google-apps.shortcut` targets, including across
  shared drives.
- **In-memory link mining** — exports Docs/Slides as `text/plain` and Sheets
  as `text/csv` (and reads plain-text files directly), regexes out URLs,
  and immediately discards the content. Google-hosted links are followed
  into the crawl queue; external links are logged but not fetched.
- **State persistence & fault tolerance** — exponential backoff with full
  jitter on 429/5xx errors, and a hidden JSON state file
  (`.linkrunner_state.json` by default) checkpointed periodically so a
  killed/interrupted run can continue with `--resume`.
- **CSV reporting** — `Links.csv` with file metadata, direct web links,
  owner emails, granted role (reader/writer/etc.), `allowFileDiscovery`
  (whether the link is search-indexable), and `detection_method` (see
  below).

## Setup

```bash
pip install --break-system-packages -r requirements.txt
```

### Authentication

Pick one:

**Service account** (recommended for org-wide, non-interactive audits —
requires domain-wide delegation or direct sharing to the service account):

```bash
python3 linkrunner.py <seed> --service-account /path/to/service-account.json
```

**OAuth (interactive)** — first run opens a browser consent screen and
caches the resulting token:

```bash
python3 linkrunner.py <seed> --oauth-client-secret /path/to/client_secret.json
```

Subsequent runs reuse the cached token (`--oauth-token`, default
`.linkrunner_oauth_token.json`) and refresh it automatically.

The API scope used is read-only: `drive.readonly`.

## Usage

```bash
# Start a new crawl from one or more seeds (Drive file/folder IDs or share links)
python3 linkrunner.py 1AbCDeFGhijKLmnoPQRstuVWxyz --service-account sa.json

python3 linkrunner.py \
  "https://drive.google.com/drive/folders/1AbCDeFGhijKLmnoPQRstuVWxyz" \
  --service-account sa.json --max-depth 6

# Resume an interrupted crawl
python3 linkrunner.py --resume --service-account sa.json

# Write reports to a specific directory, add a delay between requests
python3 linkrunner.py <seed> --service-account sa.json \
  --out-prefix ./reports --request-delay 0.25
```

### CLI options

| Flag | Description |
|---|---|
| `seeds` | Seed Drive file/folder IDs or share links (omit if `--resume`) |
| `--service-account PATH` | Service account JSON key |
| `--oauth-client-secret PATH` | OAuth client secret for interactive login |
| `--oauth-token PATH` | Cached OAuth token location |
| `--state-file PATH` | Hidden state file (default `.linkrunner_state.json`) |
| `--resume` | Resume from the existing state file |
| `--max-depth N` | Cap recursion depth |
| `--request-delay SECONDS` | Extra fixed delay between processed nodes |
| `--out-prefix DIR` | Output directory for the CSV report |

## Output

**CSV columns:** `file_id, name, mime_type, web_view_link, owner_emails,
permission_role, allow_file_discovery, detection_method, depth, discovered_at`

`depth` is how many folder/shortcut/link hops the resource is from your
seed — 0 for the seed itself, 1 for something directly inside/linked from
it, and so on.

## Notes & limits

- **Permission visibility quirk**: the Drive API only returns the full
  permissions list — including the `type: anyone` grant itself — to
  accounts that own a file or have edit/organizer access to it. A
  viewer-only account (including one whose *only* access is via a public
  "anyone with the link" grant) often gets a permissions list back that
  omits that entry. To catch this, LinkRunner falls back to an
  **unauthenticated HTTP probe** of the file's `webViewLink` whenever the
  API-visible permissions don't show a public grant: if the link loads
  without redirecting to a Google login page, the resource is still
  logged as public. The CSV's `detection_method` column tells you which
  path caught it — `api` (permission was directly visible) or `probe`
  (caught only via the anonymous reachability check). Probe-detected rows
  won't have a `permission_role`, since the API didn't hand that back —
  they're logged as `unknown (probe-detected)`.
- Only Google Workspace-native files (Docs/Sheets/Slides) and plain-text
  files are mined for links; binary formats (PDF, images, etc.) are
  logged with their metadata/permissions but their content is not parsed.
- Text content is capped at 5 MB per file and is never persisted — only
  the extracted URLs and file metadata are saved to state/reports.
- Rate-limit handling backs off automatically; use `--request-delay` for
  an additional steady-state throttle on very large drives.
