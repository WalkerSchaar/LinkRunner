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
    import requests
except ImportError:
    print(
        "Missing dependencies. Install with:\n"
        "  pip install --break-system-packages google-api-python-client "
        "google-auth-httplib2 google-auth-oauthlib requests",
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

    @staticmethod
    def probe_anonymous_access(web_view_link: str) -> bool:
        """Independent, unauthenticated check for whether a resource is truly
        reachable by anyone.

        The Drive API only returns the full permissions list (including the
        `type: anyone` entry) to accounts that own the file or have edit /
        organizer access. A viewer-only account — even one that's only able
        to view the file *because* it's shared with anyone — often gets a
        permissions list back that omits that entry entirely. This probe
        makes a plain HTTP request with no auth token at all and checks
        whether it resolves without being redirected to a Google login page,
        which is a direct test of public reachability that doesn't depend on
        what the API is willing to tell the authenticated caller.
        """
        if not web_view_link:
            return False
        try:
            resp = requests.get(
                web_view_link, allow_redirects=True, timeout=10,
                headers={"User-Agent": "Mozilla/5.0 (LinkRunner audit probe)"},
            )
            final_url = resp.url or ""
            if "accounts.google.com" in final_url or "ServiceLogin" in final_url:
                return False
            return resp.status_code == 200
        except requests.RequestException:
            return False

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
            log.warning("Could not read content of %s (%s) — link mining skipped for this file: %s",
                        file_id, mime_type, e)
            self.state.stats["errors"] += 1
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
        detection_method = "api" if is_public else None

        # The Drive API under-reports the 'anyone' permission to viewer-only
        # accounts (see probe_anonymous_access docstring). If the API-visible
        # permissions didn't show a public grant, independently verify with
        # an unauthenticated request before concluding the resource is private.
        if not is_public and mime_type not in (FOLDER_MIME, SHORTCUT_MIME):
            if self.probe_anonymous_access(meta.get("webViewLink", "")):
                is_public = True
                detection_method = "probe"

        owners = ", ".join(o.get("emailAddress", "") for o in meta.get("owners", []) or [])

        if is_public:
            self.state.stats["public_resources"] += 1
            self.state.findings.append({
                "file_id": file_id,
                "name": name,
                "mime_type": mime_type,
                "web_view_link": meta.get("webViewLink", ""),
                "owner_emails": owners,
                "permission_role": best_role or ("unknown (probe-detected)" if detection_method == "probe" else ""),
                "allow_file_discovery": allow_discovery,
                "detection_method": detection_method,
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

def _resolve_writable_path(out_path: str) -> str:
    """If out_path is locked by another process (common on Windows when the
    file is open in Excel or an editor), fall back to a numbered filename
    instead of crashing and losing the crawl results."""
    if not os.path.exists(out_path):
        return out_path
    try:
        with open(out_path, "a"):
            pass
        return out_path
    except PermissionError:
        base, ext = os.path.splitext(out_path)
        for i in range(1, 100):
            candidate = f"{base}_{i}{ext}"
            if not os.path.exists(candidate):
                log.warning(
                    "%s is locked by another program (probably open in Excel/an editor) — "
                    "writing to %s instead. Close %s and re-run to overwrite it directly next time.",
                    out_path, candidate, out_path,
                )
                return candidate
        return out_path  # give up falling back after 99 attempts; let the caller raise


def write_csv_report(state: CrawlState, out_path: str):
    out_path = _resolve_writable_path(out_path)
    fieldnames = [
        "file_id", "name", "mime_type", "web_view_link", "owner_emails",
        "permission_role", "allow_file_discovery", "detection_method", "depth", "discovered_at",
    ]
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in state.findings:
            writer.writerow(row)
    log.info("CSV report written to %s (%d public resources)", out_path, len(state.findings))



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
    parser.add_argument("--oauth-client-secret",
                         help="Path to an OAuth client_secret.json for interactive login "
                              "(auto-detected if a file named client_secret.json sits next to "
                              "this script or in the current directory)")
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

    if not args.service_account and not args.oauth_client_secret:
        for candidate in ("client_secret.json",
                           os.path.join(os.path.dirname(os.path.abspath(__file__)), "client_secret.json")):
            if os.path.exists(candidate):
                args.oauth_client_secret = candidate
                log.info("Auto-detected OAuth client secret at %s", candidate)
                break

    service = build_drive_service(args.service_account, args.oauth_token, args.oauth_client_secret)
    runner = LinkRunner(service, state, args.state_file, max_depth=args.max_depth,
                         request_delay=args.request_delay)

    try:
        runner.run()
    except KeyboardInterrupt:
        log.warning("Interrupted — saving state for resume with --resume")
        state.save(args.state_file)
        sys.exit(1)

    os.makedirs(args.out_prefix, exist_ok=True)

    csv_path = os.path.join(args.out_prefix, "Links.csv")
    write_csv_report(state, csv_path)


if __name__ == "__main__":
    main()
