#!/usr/bin/env python3

import argparse
import csv
import json
import logging
import os
import random
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from google.oauth2 import service_account
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from google.auth.transport.requests import Request
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
except ImportError:
    print(
        "Missing dependencies. Install with:\n"
        "  pip install --break-system-packages google-api-python-client "
        "google-auth-httplib2 google-auth-oauthlib",
        file=sys.stderr,
    )
    raise

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

SCOPES = ["https://www.googleapis.com/auth/drive.readonly"]

DEFAULT_STATE_FILE = ".linkrunner_state.json"

FOLDER_MIME = "application/vnd.google-apps.folder"
SHORTCUT_MIME = "application/vnd.google-apps.shortcut"

# Google Workspace mimetypes we can export as plain text for link mining.
EXPORTABLE_MIME = {
    "application/vnd.google-apps.document": "text/plain",
    "application/vnd.google-apps.presentation": "text/plain",
    "application/vnd.google-apps.spreadsheet": "text/csv",
}

# Raw text-ish files we can read directly via files.get_media without a
# Workspace export.
PLAIN_TEXT_MIME_PREFIXES = ("text/",)
PLAIN_TEXT_MIME_EXACT = {"application/json", "application/xml"}

# Cap on bytes read per file when mining for links, to keep everything
# strictly in-memory and bounded.
MAX_TEXT_BYTES = 5_000_000

GOOGLE_URL_RE = re.compile(
    r"https?://(?:[\w.-]+\.)?(?:docs|drive|sheets|slides|forms)\.google\.com/[^\s\"'<>)\]]+",
    re.IGNORECASE,
)
GENERIC_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)

DRIVE_ID_FROM_URL_RE = re.compile(
    r"(?:/folders/|/file/d/|/d/|open\?id=|id=)([a-zA-Z0-9_-]{15,})"
)

FILE_FIELDS = (
    "id,name,mimeType,webViewLink,owners(emailAddress),shortcutDetails,"
    "permissions(id,type,role,allowFileDiscovery,emailAddress),trashed,parents"
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("linkrunner")


# --------------------------------------------------------------------------
# Retry / backoff
# --------------------------------------------------------------------------

def with_backoff(func, *args, max_retries=8, base_delay=1.0, max_delay=60.0, **kwargs):
    """Call func(*args, **kwargs) with exponential backoff + full jitter on
    transient Google API errors (429 / 5xx)."""
    attempt = 0
    while True:
        try:
            return func(*args, **kwargs)
        except HttpError as e:
            status = getattr(e.resp, "status", None)
            retriable = status in (403, 429, 500, 502, 503, 504)
            # Only treat 403 as retriable if it's a rate-limit style error.
            if status == 403 and "rate" not in str(e).lower() and "quota" not in str(e).lower():
                retriable = False
            if not retriable or attempt >= max_retries:
                raise
            delay = min(max_delay, base_delay * (2 ** attempt))
            delay = random.uniform(0, delay)  # full jitter
            attempt += 1
            log.warning("API error (status=%s), backing off %.1fs (attempt %d/%d)",
                        status, delay, attempt, max_retries)
            time.sleep(delay)


# --------------------------------------------------------------------------
# State persistence
# --------------------------------------------------------------------------

@dataclass
class CrawlState:
    queue: list = field(default_factory=list)          # file/folder IDs pending visit
    visited: set = field(default_factory=set)           # file/folder IDs already processed
    findings: list = field(default_factory=list)        # audit rows (dicts)
    edges: list = field(default_factory=list)            # (src_id, dst_id_or_url, kind) for graph
    nodes: dict = field(default_factory=dict)             # id -> node metadata for graph
    started_at: str = ""
    stats: dict = field(default_factory=lambda: {
        "files_scanned": 0, "public_resources": 0, "links_mined": 0, "errors": 0
    })

    def to_json(self):
        return {
            "queue": self.queue,
            "visited": sorted(self.visited),
            "findings": self.findings,
            "edges": self.edges,
            "nodes": self.nodes,
            "started_at": self.started_at,
            "stats": self.stats,
        }

    @classmethod
    def from_json(cls, d):
        s = cls()
        s.queue = d.get("queue", [])
        s.visited = set(d.get("visited", []))
        s.findings = d.get("findings", [])
        s.edges = d.get("edges", [])
        s.nodes = d.get("nodes", {})
        s.started_at = d.get("started_at", "")
        s.stats = d.get("stats", s.stats)
        return s

    def save(self, path):
        tmp = f"{path}.tmp"
        with open(tmp, "w") as f:
            json.dump(self.to_json(), f)
        os.replace(tmp, path)

    @classmethod
    def load(cls, path):
        with open(path) as f:
            return cls.from_json(json.load(f))


# --------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------

def build_drive_service(service_account_path: Optional[str], oauth_token_path: str,
                         oauth_client_secret_path: Optional[str]):
    """Build an authenticated Drive API client. Prefers a service account if
    given, otherwise falls back to an OAuth installed-app flow (cached in
    oauth_token_path)."""
    if service_account_path:
        creds = service_account.Credentials.from_service_account_file(
            service_account_path, scopes=SCOPES
        )
        log.info("Authenticated via service account: %s", service_account_path)
        return build("drive", "v3", credentials=creds, cache_discovery=False)

    creds = None
    token_path = Path(oauth_token_path)
    if token_path.exists():
        creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not oauth_client_secret_path:
                raise SystemExit(
                    "No valid credentials found. Provide --service-account, or "
                    "--oauth-client-secret to run the interactive OAuth flow."
                )
            flow = InstalledAppFlow.from_client_secrets_file(oauth_client_secret_path, SCOPES)
            creds = flow.run_local_server(port=0)
        token_path.write_text(creds.to_json())
    log.info("Authenticated via OAuth user credentials")
    return build("drive", "v3", credentials=creds, cache_discovery=False)


# --------------------------------------------------------------------------
# Core crawler
# --------------------------------------------------------------------------

class LinkRunner:
    def __init__(self, service, state: CrawlState, state_path: str,
                 max_depth: Optional[int] = None, checkpoint_every: int = 15,
                 request_delay: float = 0.0):
        self.service = service
        self.state = state
        self.state_path = state_path
        self.max_depth = max_depth
        self.checkpoint_every = checkpoint_every
        self.request_delay = request_delay
        self._since_checkpoint = 0

    # -- Drive API wrappers -------------------------------------------------

    def get_file_metadata(self, file_id):
        return with_backoff(
            self.service.files().get(
                fileId=file_id, fields=FILE_FIELDS, supportsAllDrives=True
            ).execute
        )

    def list_children(self, folder_id):
        children = []
        page_token = None
        while True:
            resp = with_backoff(
                self.service.files().list(
                    q=f"'{folder_id}' in parents and trashed = false",
                    fields=f"nextPageToken, files({FILE_FIELDS})",
                    pageSize=200,
                    pageToken=page_token,
                    supportsAllDrives=True,
                    includeItemsFromAllDrives=True,
                ).execute
            )
            children.extend(resp.get("files", []))
            page_token = resp.get("nextPageToken")
            if not page_token:
                break
        return children

    def export_text(self, file_id, mime_type):
        export_mime = EXPORTABLE_MIME[mime_type]
        data = with_backoff(
            self.service.files().export(fileId=file_id, mimeType=export_mime).execute
        )
        if isinstance(data, bytes):
            return data[:MAX_TEXT_BYTES].decode("utf-8", errors="ignore")
        return str(data)[:MAX_TEXT_BYTES]

    def download_text(self, file_id):
        data = with_backoff(
            self.service.files().get_media(fileId=file_id).execute
        )
        if isinstance(data, bytes):
            return data[:MAX_TEXT_BYTES].decode("utf-8", errors="ignore")
        return str(data)[:MAX_TEXT_BYTES]

    # -- Seed resolution ------------------------------------------------

    @staticmethod
    def extract_id_from_link(link: str) -> Optional[str]:
        m = DRIVE_ID_FROM_URL_RE.search(link)
        return m.group(1) if m else None

    # -- Permission analysis ----------------------------------------------

    @staticmethod
    def analyze_permissions(meta: dict):
        """Return (is_public, best_role, allow_discovery) from a files.get
        permissions list."""
        is_public = False
        best_role = None
        allow_discovery = False
        role_rank = {"reader": 1, "commenter": 2, "writer": 3, "fileOrganizer": 3, "owner": 4}
        for perm in meta.get("permissions", []) or []:
            if perm.get("type") == "anyone":
                is_public = True
                role = perm.get("role")
                if role and (best_role is None or role_rank.get(role, 0) > role_rank.get(best_role, 0)):
                    best_role = role
                if perm.get("allowFileDiscovery"):
                    allow_discovery = True
        return is_public, best_role, allow_discovery

    # -- Link mining ---------------------------------------------------

    def mine_links(self, file_id: str, mime_type: str) -> list:
        """Pull text content for a file (export for Workspace types, raw
        download for plain text types) and extract URLs. Nothing is written
        to disk; text is discarded after regex extraction."""
        text = None
        try:
            if mime_type in EXPORTABLE_MIME:
                text = self.export_text(file_id, mime_type)
            elif mime_type.startswith(PLAIN_TEXT_MIME_PREFIXES) or mime_type in PLAIN_TEXT_MIME_EXACT:
                text = self.download_text(file_id)
        except HttpError as e:
            log.debug("Could not read content of %s (%s): %s", file_id, mime_type, e)
            return []
        if not text:
            return []

        found = set(GENERIC_URL_RE.findall(text))
        text = None  # discard reference to content immediately
        return sorted(found)

    # -- Main crawl loop -------------------------------------------------

    def enqueue(self, file_id, depth=0):
        if file_id not in self.state.visited and file_id not in [q[0] for q in self.state.queue]:
            self.state.queue.append((file_id, depth))

    def run(self):
        if not self.state.started_at:
            self.state.started_at = datetime.now(timezone.utc).isoformat()

        while self.state.queue:
            file_id, depth = self.state.queue.pop(0)
            if file_id in self.state.visited:
                continue
            if self.max_depth is not None and depth > self.max_depth:
                continue

            try:
                self.process_node(file_id, depth)
            except HttpError as e:
                log.error("Giving up on %s after retries: %s", file_id, e)
                self.state.stats["errors"] += 1
            finally:
                self.state.visited.add(file_id)
                self._since_checkpoint += 1
                if self._since_checkpoint >= self.checkpoint_every:
                    self.state.save(self.state_path)
                    self._since_checkpoint = 0
                if self.request_delay:
                    time.sleep(self.request_delay)

        self.state.save(self.state_path)
        log.info("Crawl complete. Stats: %s", self.state.stats)

    def process_node(self, file_id, depth):
        meta = self.get_file_metadata(file_id)
        name = meta.get("name", "<unknown>")
        mime_type = meta.get("mimeType", "")
        log.info("[depth %d] Visiting %s (%s)", depth, name, file_id)
        self.state.stats["files_scanned"] += 1

        self.state.nodes[file_id] = {
            "id": file_id,
            "name": name,
            "mimeType": mime_type,
            "type": "folder" if mime_type == FOLDER_MIME else "file",
        }

        # Resolve shortcuts and continue traversal through the target.
        if mime_type == SHORTCUT_MIME:
            target_id = meta.get("shortcutDetails", {}).get("targetId")
            if target_id:
                self.state.edges.append((file_id, target_id, "shortcut"))
                self.enqueue(target_id, depth)
            return

        is_public, best_role, allow_discovery = self.analyze_permissions(meta)
        owners = ", ".join(o.get("emailAddress", "") for o in meta.get("owners", []) or [])

        if is_public:
            self.state.stats["public_resources"] += 1
            self.state.findings.append({
                "file_id": file_id,
                "name": name,
                "mime_type": mime_type,
                "web_view_link": meta.get("webViewLink", ""),
                "owner_emails": owners,
                "permission_role": best_role or "",
                "allow_file_discovery": allow_discovery,
                "depth": depth,
                "discovered_at": datetime.now(timezone.utc).isoformat(),
            })
            self.state.nodes[file_id]["public"] = True
            self.state.nodes[file_id]["role"] = best_role

        # Recurse into folders.
        if mime_type == FOLDER_MIME:
            for child in self.list_children(file_id):
                self.state.edges.append((file_id, child["id"], "contains"))
                self.enqueue(child["id"], depth + 1)
            return

        # Mine text content of documents for embedded links.
        if mime_type in EXPORTABLE_MIME or mime_type.startswith(PLAIN_TEXT_MIME_PREFIXES) \
                or mime_type in PLAIN_TEXT_MIME_EXACT:
            urls = self.mine_links(file_id, mime_type)
            self.state.stats["links_mined"] += len(urls)
            for url in urls:
                target_id = self.extract_id_from_link(url) if GOOGLE_URL_RE.match(url) else None
                kind = "google_link" if target_id else "external_link"
                self.state.edges.append((file_id, target_id or url, kind))
                if target_id:
                    self.enqueue(target_id, depth + 1)
                else:
                    self.state.nodes.setdefault(url, {"id": url, "name": url, "type": "external"})


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def write_csv_report(state: CrawlState, out_path: str):
    fieldnames = [
        "file_id", "name", "mime_type", "web_view_link", "owner_emails",
        "permission_role", "allow_file_discovery", "depth", "discovered_at",
    ]
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in state.findings:
            writer.writerow(row)
    log.info("CSV report written to %s (%d public resources)", out_path, len(state.findings))


def write_html_graph(state: CrawlState, out_path: str):
    """Render an interactive vis-network graph of the crawl: nodes are Drive
    files/folders/external URLs, edges are containment/shortcut/link
    relationships. Public resources are highlighted."""
    nodes = []
    node_ids_seen = set()
    for nid, meta in state.nodes.items():
        color = "#5b8def"
        shape = "dot"
        if meta.get("type") == "folder":
            color = "#f2c14e"
            shape = "box"
        elif meta.get("type") == "external":
            color = "#9e9e9e"
            shape = "diamond"
        if meta.get("public"):
            color = "#e5484d"  # red = publicly exposed
        label = meta.get("name", nid)
        if len(label) > 40:
            label = label[:37] + "..."
        nodes.append({
            "id": nid,
            "label": label,
            "color": color,
            "shape": shape,
            "title": json.dumps(meta, indent=2)[:500],
        })
        node_ids_seen.add(nid)

    edges = []
    edge_colors = {"contains": "#888888", "shortcut": "#b46fd1", "google_link": "#5b8def", "external_link": "#cccccc"}
    for src, dst, kind in state.edges:
        if src not in node_ids_seen or dst not in node_ids_seen:
            continue
        edges.append({
            "from": src, "to": dst,
            "color": edge_colors.get(kind, "#aaaaaa"),
            "title": kind,
            "dashes": kind in ("external_link", "google_link"),
        })

    html = HTML_TEMPLATE.replace("__NODES__", json.dumps(nodes)) \
                         .replace("__EDGES__", json.dumps(edges)) \
                         .replace("__STATS__", json.dumps(state.stats, indent=2)) \
                         .replace("__GENERATED__", datetime.now(timezone.utc).isoformat())
    with open(out_path, "w") as f:
        f.write(html)
    log.info("HTML graph written to %s", out_path)


HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>LinkRunner Crawl Graph</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.6/vis-network.min.js"></script>
<style>
  html, body { margin:0; height:100%; font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0f1117; color:#e6e6e6; }
  #header { padding:12px 20px; border-bottom:1px solid #2a2d38; display:flex; justify-content:space-between; align-items:center; }
  #header h1 { font-size:16px; margin:0; }
  #legend { font-size:12px; color:#aaa; }
  #legend span { margin-left:14px; }
  .dot { display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:4px; vertical-align:middle; }
  #network { width:100%; height:calc(100% - 52px); }
  #stats { position:absolute; top:60px; right:20px; background:#181b24; border:1px solid #2a2d38; border-radius:8px; padding:10px 14px; font-size:12px; white-space:pre; }
</style>
</head>
<body>
<div id="header">
  <h1>LinkRunner &mdash; Drive Exposure Graph <span style="color:#777;font-weight:normal;">generated __GENERATED__</span></h1>
  <div id="legend">
    <span><i class="dot" style="background:#e5484d"></i>Publicly exposed</span>
    <span><i class="dot" style="background:#f2c14e"></i>Folder</span>
    <span><i class="dot" style="background:#5b8def"></i>File</span>
    <span><i class="dot" style="background:#9e9e9e"></i>External link</span>
  </div>
</div>
<div id="network"></div>
<div id="stats">__STATS__</div>
<script>
  const nodes = new vis.DataSet(__NODES__);
  const edges = new vis.DataSet(__EDGES__);
  const container = document.getElementById('network');
  const data = { nodes, edges };
  const options = {
    nodes: { font: { color: '#e6e6e6', size: 13 }, borderWidth: 1 },
    edges: { arrows: 'to', smooth: { type: 'dynamic' } },
    physics: { stabilization: true, barnesHut: { gravitationalConstant: -3000, springLength: 120 } },
    interaction: { hover: true, tooltipDelay: 100 }
  };
  new vis.Network(container, data, options);
</script>
</body>
</html>
"""


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="LinkRunner: audit a Google Drive environment for publicly "
                     "exposed ('anyone with the link') resources and mine embedded links."
    )
    parser.add_argument("seeds", nargs="*", help="Seed Drive file/folder IDs or share links")
    parser.add_argument("--service-account", help="Path to a service account JSON key")
    parser.add_argument("--oauth-client-secret", help="Path to an OAuth client_secret.json for interactive login")
    parser.add_argument("--oauth-token", default=".linkrunner_oauth_token.json",
                         help="Where to cache/read OAuth user credentials")
    parser.add_argument("--state-file", default=DEFAULT_STATE_FILE, help="Hidden state file for resume support")
    parser.add_argument("--resume", action="store_true", help="Resume from an existing state file")
    parser.add_argument("--max-depth", type=int, default=None, help="Maximum recursion depth")
    parser.add_argument("--request-delay", type=float, default=0.0,
                         help="Fixed delay (seconds) between processed nodes, on top of backoff")
    parser.add_argument("--out-prefix", default=".", help="Directory to write CSV/HTML reports into")
    args = parser.parse_args()

    if args.resume:
        if not os.path.exists(args.state_file):
            parser.error(f"--resume given but state file {args.state_file} does not exist")
        state = CrawlState.load(args.state_file)
        log.info("Resumed state: %d queued, %d visited, %d findings",
                 len(state.queue), len(state.visited), len(state.findings))
    else:
        if not args.seeds:
            parser.error("Provide at least one seed file/folder ID or link, or use --resume")
        state = CrawlState()
        for seed in args.seeds:
            seed_id = LinkRunner.extract_id_from_link(seed) if seed.startswith("http") else seed
            if not seed_id:
                log.warning("Could not parse an ID out of seed %r, skipping", seed)
                continue
            state.queue.append((seed_id, 0))

    service = build_drive_service(args.service_account, args.oauth_token, args.oauth_client_secret)
    runner = LinkRunner(service, state, args.state_file, max_depth=args.max_depth,
                         request_delay=args.request_delay)

    try:
        runner.run()
    except KeyboardInterrupt:
        log.warning("Interrupted — saving state for resume with --resume")
        state.save(args.state_file)
        sys.exit(1)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    csv_path = os.path.join(args.out_prefix, f"anon-link-audit-{timestamp}.csv")
    html_path = os.path.join(args.out_prefix, f"linkrunner-graph-{timestamp}.html")
    write_csv_report(state, csv_path)
    write_html_graph(state, html_path)


if __name__ == "__main__":
    main()
