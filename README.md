# LinkRunner

LinkRunner is a Google Drive exposure-auditing tool. Starting from one or
more seed folders/files, it recursively crawls a Drive environment,
resolves shortcuts across drives, flags any resource shared with
**"anyone with the link"** (`type="anyone"`), mines the plain-text content
of Docs/Sheets/Slides/text files for embedded links (in memory only —
nothing is written to disk), and produces a CSV audit report plus an
interactive HTML graph of what it found.

It's an updated, single-file rewrite in the spirit of
[PaperChaser](https://github.com/mandatoryprogrammer/PaperChaser), aimed at
letting you (or your org) find accidental zero-authentication exposure in
your own Drive.



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
| `--out-prefix DIR` | Output directory for CSV/HTML reports |

## Output

**CSV columns:** `file_id, name, mime_type, web_view_link, owner_emails,
permission_role, allow_file_discovery, depth, discovered_at`

**HTML graph:** open the file in a browser. Red nodes are publicly
exposed; yellow are folders; blue are Drive files; grey diamonds are
external links found in document text. Hover a node for its metadata.

## Notes & limits

- Only Google Workspace-native files (Docs/Sheets/Slides) and plain-text
  files are mined for links; binary formats (PDF, images, etc.) are
  logged with their metadata/permissions but their content is not parsed.
- Text content is capped at 5 MB per file and is never persisted — only
  the extracted URLs and file metadata are saved to state/reports.
- Rate-limit handling backs off automatically; use `--request-delay` for
  an additional steady-state throttle on very large drives.
