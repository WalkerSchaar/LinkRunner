#!/usr/bin/env python3

import argparse
import csv
import io
import json
import os
import random
import re
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google.oauth2 import service_account
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
except ImportError:
    Image = None

try:
    import cv2
    import numpy as np
except ImportError:
    cv2 = None

SCOPES = [
    "https://www.googleapis.com/auth/drive.readonly",
    "https://www.googleapis.com/auth/spreadsheets.readonly",
]

TOKEN_PATH = "token.json"
CREDS_PATH = "credentials.json"
SERVICE_ACCOUNT_PATH = "service_account.json"

# Skip downloading raw bytes of anything bigger than this (PDF/Office scan).
MAX_DOWNLOAD_BYTES = 30 * 1024 * 1024  # 30 MB

# ---------------------------------------------------------------------------
# URL / ID patterns
# ---------------------------------------------------------------------------

FILE_ID_PATTERNS = [
    r"docs\.google\.com/document/d/([a-zA-Z0-9_-]{15,})",
    r"docs\.google\.com/spreadsheets/d/([a-zA-Z0-9_-]{15,})",
    r"docs\.google\.com/presentation/d/([a-zA-Z0-9_-]{15,})",
    r"docs\.google\.com/forms/d/([a-zA-Z0-9_-]{15,})",
    r"drive\.google\.com/file/d/([a-zA-Z0-9_-]{15,})",
    r"drive\.google\.com/drive/folders/([a-zA-Z0-9_-]{15,})",
    r"drive\.google\.com/drive/u/\d+/folders/([a-zA-Z0-9_-]{15,})",
    r"drive\.google\.com/open\?id=([a-zA-Z0-9_-]{15,})",
    r"[?&]id=([a-zA-Z0-9_-]{15,})",
]
FILE_ID_RE = re.compile("|".join(FILE_ID_PATTERNS))

GENERIC_URL_RE = re.compile(r"https?://[^\s\"'<>\)\]]+")

# Non-Drive-API Google products worth flagging separately -- the crawler
# can't enumerate their contents, but a link to one is a real finding
# (e.g. a Site or Colab notebook shared the same over-permissive way).
GOOGLE_OTHER_DOMAINS = [
    "sites.google.com",
    "colab.research.google.com",
    "jamboard.google.com",
    "groups.google.com",
    "calendar.google.com",
    "meet.google.com",
    "chat.google.com",
]

# Other cloud storage / collab platforms -- a link to one of these is
# evidence the same "share by link" habit extends outside Google Drive
# entirely, which is usually the most actionable finding in this category.
CLOUD_STORAGE_DOMAINS = [
    "dropbox.com",
    "box.com",
    "app.box.com",
    "onedrive.live.com",
    "1drv.ms",
    "sharepoint.com",
    "s3.amazonaws.com",
    "storage.googleapis.com",
    "blob.core.windows.net",
    "notion.so",
    "notion.site",
    "airtable.com",
    "atlassian.net",  # Confluence/Jira cloud instances
    "wetransfer.com",
]

# Domains whose response typically indicates "you need to log in" rather
# than actual content, used by the reachability check below.
LOGIN_REDIRECT_MARKERS = [
    "accounts.google.com",
    "login.microsoftonline.com",
    "login.live.com",
    "www.dropbox.com/login",
    "account.box.com/login",
    "atlassian.net/login",
]

EXPORTABLE_MIME_TYPES = {
    "application/vnd.google-apps.document": "text/plain",
    "application/vnd.google-apps.presentation": "text/plain",
    # Sheets are handled separately via the Sheets API (fetch_sheet_all_tabs_text)
    # for full multi-tab hyperlink coverage, not this simple export endpoint.
}

OOXML_ZIP_MIME_TYPES = {
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}

# Legacy OLE-binary Office formats. No lightweight pure-Python parser
# extracts hyperlinks from these reliably, so we fall back to a
# strings(1)-style heuristic: pull printable ASCII and UTF-16LE runs out
# of the raw bytes and regex-scan those. Good enough for link discovery.
LEGACY_OFFICE_MIME_TYPES = {
    "application/msword",
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
}

PLAIN_TEXT_MIME_TYPES = {
    "text/plain",
    "application/rtf",
    "text/rtf",
}

# Gated behind --scan-images since it's the heaviest/slowest scan (EXIF
# read via Pillow + QR decode via OpenCV) and least often fruitful.
IMAGE_MIME_TYPES = {
    "image/jpeg", "image/png", "image/tiff", "image/bmp", "image/webp",
}

SHEETS_NATIVE_MIME = "application/vnd.google-apps.spreadsheet"
PDF_MIME = "application/pdf"
FOLDER_MIME = "application/vnd.google-apps.folder"

MAIN_CSV_FIELDS = [
    "file_id", "name", "mime_type", "web_view_link", "owners",
    "shared", "permission_types", "created_time", "modified_time",
    "size", "depth", "discovery_method", "discovered_from", "seed_source", "error",
]

EXTERNAL_CSV_FIELDS = [
    "url", "category", "reachable", "discovered_from_file_id", "depth", "seed_source",
]


@dataclass
class CrawlState:
    to_crawl: deque = field(default_factory=deque)
    crawled_ids: set = field(default_factory=set)
    queued_ids: set = field(default_factory=set)
    logged_external: set = field(default_factory=set)
    main_rows: list = field(default_factory=list)   # kept in memory for optional graph export
    ext_rows: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def load_credentials():
    if os.path.exists(SERVICE_ACCOUNT_PATH):
        return service_account.Credentials.from_service_account_file(
            SERVICE_ACCOUNT_PATH, scopes=SCOPES
        )
    creds = None
    if os.path.exists(TOKEN_PATH):
        creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists(CREDS_PATH):
                sys.exit(
                    f"[ERROR] Missing {CREDS_PATH} (OAuth client) or "
                    f"{SERVICE_ACCOUNT_PATH} (service account). See README.md."
                )
            flow = InstalledAppFlow.from_client_secrets_file(CREDS_PATH, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(TOKEN_PATH, "w") as f:
            f.write(creds.to_json())
    return creds


# ---------------------------------------------------------------------------
# Link extraction helpers
# ---------------------------------------------------------------------------

def extract_file_ids(text):
    ids = set()
    for match in FILE_ID_RE.finditer(text or ""):
        file_id = next(g for g in match.groups() if g)
        ids.add(file_id)
    return ids


def classify_external_url(url):
    for domain in GOOGLE_OTHER_DOMAINS:
        if domain in url:
            return "google_other"
    for domain in CLOUD_STORAGE_DOMAINS:
        if domain in url:
            return "cloud_storage"
    return "external_other"


def extract_external_links(text, include_all=False):
    """URLs that are NOT a recognized Drive file/folder link -- i.e. things
    this tool can't crawl into but should still report as findings.

    By default only 'google_other' and 'cloud_storage' links are returned
    -- these represent real additional attack surface (the same
    share-by-link pattern on another platform). Generic external links
    (news sites, vendor pages, etc.) are noise for an attack-surface view
    and are dropped unless include_all=True.
    """
    results = []
    for url in GENERIC_URL_RE.finditer(text or ""):
        u = url.group(0).rstrip(").,;'\"")
        if FILE_ID_RE.search(u):
            continue  # already captured as a crawlable Drive link
        category = classify_external_url(u)
        if category == "external_other" and not include_all:
            continue
        results.append((u, category))
    return results


def check_reachability(url, timeout=8):
    """Unauthenticated probe: does this link actually serve content to
    someone with no session, or does it bounce to a login page / block?
    Returns 'reachable', 'login_required', 'blocked', or 'unknown'.
    """
    try:
        import requests
    except ImportError:
        return "unknown (requests not installed)"
    try:
        resp = requests.get(
            url, timeout=timeout, allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; LinkRunner-reachability-check)"},
        )
        final_url = resp.url or ""
        if any(marker in final_url for marker in LOGIN_REDIRECT_MARKERS):
            return "login_required"
        if resp.status_code in (401, 403):
            return "blocked"
        if resp.status_code >= 400:
            return f"error_{resp.status_code}"
        return "reachable"
    except Exception as e:
        return f"unknown ({type(e).__name__})"


def extract_from_ooxml_zip(data: bytes) -> str:
    """docx/xlsx/pptx are zips of XML -- concatenate the XML parts (which
    include document.xml and the _rels hyperlink targets) so the normal
    URL regexes can scan them."""
    import zipfile
    chunks = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                if name.endswith(".xml") or name.endswith(".rels"):
                    try:
                        chunks.append(zf.read(name).decode("utf-8", errors="ignore"))
                    except Exception:
                        continue
    except Exception as e:
        print(f"[WARN] Could not open OOXML zip: {e}")
    return "\n".join(chunks)


def extract_from_pdf(data: bytes) -> str:
    """Concatenate extracted text plus any /URI link-annotation targets,
    since PDF hyperlinks often aren't present in the visible text."""
    if PdfReader is None:
        print("[WARN] pypdf not installed -- skipping PDF link extraction")
        return ""
    chunks = []
    try:
        reader = PdfReader(io.BytesIO(data))
        for page in reader.pages:
            try:
                chunks.append(page.extract_text() or "")
            except Exception:
                pass
            annots = page.get("/Annots")
            if not annots:
                continue
            for a in annots:
                try:
                    obj = a.get_object()
                    uri = obj.get("/A", {}).get("/URI")
                    if uri:
                        chunks.append(str(uri))
                except Exception:
                    continue
    except Exception as e:
        print(f"[WARN] Could not parse PDF: {e}")
    return "\n".join(chunks)


def extract_strings_heuristic(data: bytes, min_len: int = 6) -> str:
    """strings(1)-style extraction for formats with no lightweight parser
    (legacy .doc/.xls/.ppt). Pulls printable-ASCII runs and UTF-16LE runs
    out of the raw bytes; hyperlink targets in these binary formats are
    almost always stored as literal readable text somewhere in the file,
    so this catches them without needing a full OLE/CFB parser."""
    ascii_run_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    chunks = [m.group().decode("ascii", errors="ignore") for m in ascii_run_re.finditer(data)]

    # UTF-16LE text (common in Word 97-2003 streams): printable ASCII byte
    # followed by a null byte, repeated.
    utf16_run_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    for m in utf16_run_re.finditer(data):
        try:
            chunks.append(m.group().decode("utf-16-le", errors="ignore"))
        except Exception:
            continue
    return "\n".join(chunks)


def extract_from_text_bytes(data: bytes) -> str:
    """.txt and .rtf are already plain text (RTF's HYPERLINK field syntax
    keeps the literal URL as readable ASCII), so just decode."""
    return data.decode("utf-8", errors="ignore")


def extract_from_image(data: bytes) -> str:
    """Pull URLs out of EXIF text fields (UserComment/ImageDescription/
    Artist/Copyright, etc. occasionally carry a link) and out of any QR
    codes rendered in the image itself."""
    chunks = []

    if Image is not None:
        try:
            img = Image.open(io.BytesIO(data))
            exif = img.getexif()
            for tag_id, value in exif.items():
                tag = TAGS.get(tag_id, tag_id)
                if isinstance(value, bytes):
                    value = value.decode("utf-8", errors="ignore")
                if isinstance(value, str):
                    chunks.append(f"{tag}: {value}")
        except Exception as e:
            print(f"[WARN] Could not read EXIF: {e}")
    else:
        print("[WARN] Pillow not installed -- skipping EXIF read")

    if cv2 is not None:
        try:
            arr = np.frombuffer(data, dtype=np.uint8)
            cv_img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
            if cv_img is not None:
                detector = cv2.QRCodeDetector()
                ok, decoded_texts, _, _ = detector.detectAndDecodeMulti(cv_img)
                if ok:
                    chunks.extend(t for t in decoded_texts if t)
        except Exception as e:
            print(f"[WARN] Could not run QR detection: {e}")
    else:
        print("[WARN] opencv-python not installed -- skipping QR code scan")

    return "\n".join(chunks)


def fetch_sheet_all_tabs_text(sheets_service, spreadsheet_id):
    """Full multi-tab walk via the Sheets API: pulls every cell's
    hyperlink (explicit link, not just visible text) and formatted value
    across every sheet/tab, not just the first one CSV export would give."""
    try:
        resp = with_backoff(
            lambda: sheets_service.spreadsheets().get(
                spreadsheetId=spreadsheet_id,
                includeGridData=True,
                fields="sheets(properties(title),"
                       "data(rowData(values(hyperlink,formattedValue,"
                       "userEnteredValue(formulaValue)))))",
            ).execute()
        )
    except HttpError as e:
        print(f"[WARN] Could not read spreadsheet {spreadsheet_id} via Sheets API: {e}")
        return ""

    chunks = []
    for sheet in resp.get("sheets", []):
        for grid in sheet.get("data", []):
            for row in grid.get("rowData", []):
                for cell in row.get("values", []):
                    if cell.get("hyperlink"):
                        chunks.append(cell["hyperlink"])
                    if cell.get("formattedValue"):
                        chunks.append(cell["formattedValue"])
                    formula = cell.get("userEnteredValue", {}).get("formulaValue")
                    if formula:
                        chunks.append(formula)
    return "\n".join(chunks)


# ---------------------------------------------------------------------------
# Drive API calls (with backoff)
# ---------------------------------------------------------------------------

def with_backoff(func, max_retries=6):
    for attempt in range(max_retries):
        try:
            return func()
        except HttpError as e:
            status = getattr(e, "status_code", None) or e.resp.status
            if status in (403, 429, 500, 502, 503) and attempt < max_retries - 1:
                delay = (2 ** attempt) + random.uniform(0, 1)
                print(f"[WARN] HTTP {status}, backing off {delay:.1f}s...")
                time.sleep(delay)
                continue
            raise


def fetch_metadata(drive_service, file_id):
    fields = (
        "id,name,mimeType,webViewLink,owners(emailAddress),shared,"
        "createdTime,modifiedTime,size,permissions(type,role,domain,emailAddress),driveId"
    )
    return with_backoff(
        lambda: drive_service.files().get(
            fileId=file_id, fields=fields, supportsAllDrives=True
        ).execute()
    )


def fetch_exported_text(drive_service, file_id, mime_type):
    export_mime = EXPORTABLE_MIME_TYPES.get(mime_type)
    if not export_mime:
        return ""
    try:
        content = with_backoff(
            lambda: drive_service.files()
            .export(fileId=file_id, mimeType=export_mime)
            .execute()
        )
        return content.decode("utf-8", errors="ignore") if isinstance(content, bytes) else content
    except HttpError as e:
        print(f"[WARN] Could not export {file_id}: {e}")
        return ""


def fetch_raw_bytes(drive_service, file_id, size_str):
    try:
        size = int(size_str) if size_str else 0
    except ValueError:
        size = 0
    if size and size > MAX_DOWNLOAD_BYTES:
        print(f"[WARN] Skipping download of {file_id} ({size} bytes, over limit)")
        return None
    try:
        return with_backoff(
            lambda: drive_service.files().get_media(fileId=file_id).execute()
        )
    except HttpError as e:
        print(f"[WARN] Could not download {file_id}: {e}")
        return None


def list_folder_children(drive_service, folder_id):
    children = []
    page_token = None
    while True:
        resp = with_backoff(
            lambda: drive_service.files().list(
                q=f"'{folder_id}' in parents and trashed = false",
                fields="nextPageToken, files(id, name, mimeType)",
                pageSize=1000,
                includeItemsFromAllDrives=True,
                supportsAllDrives=True,
                corpora="allDrives",
                pageToken=page_token,
            ).execute()
        )
        children.extend(resp.get("files", []))
        page_token = resp.get("nextPageToken")
        if not page_token:
            break
    return children


# ---------------------------------------------------------------------------
# Optional: graph export
# ---------------------------------------------------------------------------

def export_graph(main_rows, ext_rows, output_path):
    """Build a directed graph from the crawl (Drive objects + external
    resources as nodes, discovery relationships as edges) and export it
    for visualization/analysis with networkx / Gephi / etc."""
    try:
        import networkx as nx
    except ImportError:
        print("[WARN] networkx not installed -- skipping graph export (pip install networkx)")
        return

    g = nx.DiGraph()
    for row in main_rows:
        g.add_node(
            row["file_id"], label=row.get("name", ""), node_type="drive_file",
            mime_type=row.get("mime_type", ""), depth=row.get("depth", ""),
            permission_types=row.get("permission_types", ""),
        )
        if row.get("discovered_from"):
            g.add_edge(row["discovered_from"], row["file_id"],
                       method=row.get("discovery_method", ""))

    for row in ext_rows:
        g.add_node(
            row["url"], label=row["url"], node_type="external",
            category=row.get("category", ""), reachable=row.get("reachable", ""),
        )
        if row.get("discovered_from_file_id"):
            g.add_edge(row["discovered_from_file_id"], row["url"], method="external_link")

    ext = os.path.splitext(output_path)[1].lower()
    try:
        if ext == ".gexf":
            nx.write_gexf(g, output_path)
        elif ext == ".dot":
            nx.drawing.nx_pydot.write_dot(g, output_path)
        else:
            if ext != ".graphml":
                output_path += ".graphml"
            nx.write_graphml(g, output_path)
    except Exception as e:
        print(f"[WARN] Could not write graph: {e}")
        return

    print(f"[NOTICE] Graph exported to {output_path} "
          f"({g.number_of_nodes()} nodes, {g.number_of_edges()} edges)")


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------

def load_seeds(seed_path):
    with open(seed_path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def load_resume_state(resume_path):
    if resume_path and os.path.exists(resume_path):
        with open(resume_path) as f:
            return set(json.load(f).get("crawled_ids", []))
    return set()


def save_resume_state(resume_path, crawled_ids):
    if resume_path:
        with open(resume_path, "w") as f:
            json.dump({"crawled_ids": sorted(crawled_ids)}, f)


def domain_allowed(email_or_domain, domain_filter):
    if not domain_filter:
        return True
    return domain_filter.lower() in (email_or_domain or "").lower()


# ---------------------------------------------------------------------------
# Core crawl
# ---------------------------------------------------------------------------

def crawl(seed_path, output_csv, external_csv, max_depth=6, domain_filter=None,
          delay=0.5, resume_path=None, scan_binaries=True,
          include_all_external=False, check_reachable=False,
          scan_images=False, graph_output=None):
    creds = load_credentials()
    drive_service = build("drive", "v3", credentials=creds)
    sheets_service = build("sheets", "v4", credentials=creds)

    seeds = load_seeds(seed_path)
    if not seeds:
        sys.exit(f"[ERROR] No seed URLs found in {seed_path}")

    state = CrawlState()
    state.crawled_ids |= load_resume_state(resume_path)

    for seed in seeds:
        for file_id in extract_file_ids(seed):
            if file_id not in state.crawled_ids and file_id not in state.queued_ids:
                state.to_crawl.append((file_id, 0, None, seed, "seed"))
                state.queued_ids.add(file_id)

    if not state.to_crawl and not state.crawled_ids:
        sys.exit("[ERROR] No valid Drive file/folder IDs found in seed file.")

    write_main_header = not (os.path.exists(output_csv) and os.path.getsize(output_csv) > 0)
    main_file = open(output_csv, "a", newline="", encoding="utf-8")
    main_writer = csv.DictWriter(main_file, fieldnames=MAIN_CSV_FIELDS)
    if write_main_header:
        main_writer.writeheader()

    write_ext_header = not (os.path.exists(external_csv) and os.path.getsize(external_csv) > 0)
    ext_file = open(external_csv, "a", newline="", encoding="utf-8")
    ext_writer = csv.DictWriter(ext_file, fieldnames=EXTERNAL_CSV_FIELDS)
    if write_ext_header:
        ext_writer.writeheader()

    print(f"[NOTICE] Drive objects -> {output_csv}")
    print(f"[NOTICE] External/other-product resources -> {external_csv}")

    found_count = 0
    external_count = 0

    def log_external(links, discovered_from, depth, seed_source):
        nonlocal external_count
        for url, category in links:
            key = (url, discovered_from)
            if key in state.logged_external:
                continue
            state.logged_external.add(key)
            reachable = check_reachability(url) if check_reachable else "not_checked"
            ext_row = {
                "url": url, "category": category, "reachable": reachable,
                "discovered_from_file_id": discovered_from or "",
                "depth": depth, "seed_source": seed_source,
            }
            ext_writer.writerow(ext_row)
            state.ext_rows.append(ext_row)
            external_count += 1
        if links:
            ext_file.flush()

    def drain_queue():
        """Process everything currently queued -- the BFS/expansion loop."""
        nonlocal found_count
        while state.to_crawl:
            file_id, depth, discovered_from, seed_source, discovery_method = state.to_crawl.popleft()
            state.queued_ids.discard(file_id)
            if file_id in state.crawled_ids:
                continue
            state.crawled_ids.add(file_id)

            row = {
                "file_id": file_id, "name": "", "mime_type": "", "web_view_link": "",
                "owners": "", "shared": "", "permission_types": "", "created_time": "",
                "modified_time": "", "size": "", "depth": depth,
                "discovery_method": discovery_method,
                "discovered_from": discovered_from or "", "seed_source": seed_source, "error": "",
            }

            try:
                meta = fetch_metadata(drive_service, file_id)
            except HttpError as e:
                row["error"] = f"HTTP {e.resp.status}"
                main_writer.writerow(row)
                main_file.flush()
                state.main_rows.append(row)
                print(f"[STATUS] {file_id}: error ({row['error']}), "
                      f"queue={len(state.to_crawl)} crawled={len(state.crawled_ids)}")
                continue

            owners = ",".join(o.get("emailAddress", "") for o in meta.get("owners", []))
            perms = meta.get("permissions", []) or []
            perm_types = ",".join(sorted({p.get("type", "") for p in perms}))
            mime_type = meta.get("mimeType", "")

            row.update({
                "name": meta.get("name", ""), "mime_type": mime_type,
                "web_view_link": meta.get("webViewLink", ""), "owners": owners,
                "shared": meta.get("shared", ""), "permission_types": perm_types,
                "created_time": meta.get("createdTime", ""),
                "modified_time": meta.get("modifiedTime", ""), "size": meta.get("size", ""),
            })
            main_writer.writerow(row)
            main_file.flush()
            state.main_rows.append(row)
            found_count += 1

            print(f"[STATUS] [{discovery_method}] '{row['name']}' ({file_id}) "
                  f"[{mime_type.split('.')[-1]}] depth={depth}, "
                  f"queue={len(state.to_crawl)} crawled={len(state.crawled_ids)}")

            if not domain_allowed(owners, domain_filter):
                save_resume_state(resume_path, state.crawled_ids)
                continue

            if depth >= max_depth:
                save_resume_state(resume_path, state.crawled_ids)
                continue

            # --- Expand based on type ---
            text_to_scan = ""
            if mime_type == FOLDER_MIME:
                children = list_folder_children(drive_service, file_id)
                for child in children:
                    cid = child["id"]
                    if cid not in state.crawled_ids and cid not in state.queued_ids:
                        state.to_crawl.append((cid, depth + 1, file_id, seed_source, "folder_listing"))
                        state.queued_ids.add(cid)
            elif mime_type == SHEETS_NATIVE_MIME:
                text_to_scan = fetch_sheet_all_tabs_text(sheets_service, file_id)
            elif mime_type in EXPORTABLE_MIME_TYPES:
                text_to_scan = fetch_exported_text(drive_service, file_id, mime_type)
            elif scan_binaries and mime_type == PDF_MIME:
                data = fetch_raw_bytes(drive_service, file_id, row["size"])
                if data:
                    text_to_scan = extract_from_pdf(data)
            elif scan_binaries and mime_type in OOXML_ZIP_MIME_TYPES:
                data = fetch_raw_bytes(drive_service, file_id, row["size"])
                if data:
                    text_to_scan = extract_from_ooxml_zip(data)
            elif scan_binaries and mime_type in LEGACY_OFFICE_MIME_TYPES:
                data = fetch_raw_bytes(drive_service, file_id, row["size"])
                if data:
                    text_to_scan = extract_strings_heuristic(data)
            elif scan_binaries and mime_type in PLAIN_TEXT_MIME_TYPES:
                data = fetch_raw_bytes(drive_service, file_id, row["size"])
                if data:
                    text_to_scan = extract_from_text_bytes(data)
            elif scan_images and mime_type in IMAGE_MIME_TYPES:
                data = fetch_raw_bytes(drive_service, file_id, row["size"])
                if data:
                    text_to_scan = extract_from_image(data)

            if text_to_scan:
                new_ids = extract_file_ids(text_to_scan) - state.crawled_ids - state.queued_ids
                method_by_mime = {
                    SHEETS_NATIVE_MIME: "sheet_link", PDF_MIME: "pdf_text",
                }
                for new_id in new_ids:
                    if mime_type in method_by_mime:
                        method = method_by_mime[mime_type]
                    elif mime_type in OOXML_ZIP_MIME_TYPES:
                        method = "office_text"
                    elif mime_type in LEGACY_OFFICE_MIME_TYPES:
                        method = "legacy_office_text"
                    elif mime_type in PLAIN_TEXT_MIME_TYPES:
                        method = "text_file"
                    elif mime_type in IMAGE_MIME_TYPES:
                        method = "image_scan"
                    else:
                        method = "doc_link"
                    state.to_crawl.append((new_id, depth + 1, file_id, seed_source, method))
                    state.queued_ids.add(new_id)

                external_links = extract_external_links(text_to_scan, include_all=include_all_external)
                log_external(external_links, file_id, depth, seed_source)

            save_resume_state(resume_path, state.crawled_ids)
            time.sleep(delay + random.uniform(0, 0.3))

    try:
        drain_queue()
    except KeyboardInterrupt:
        print("\n[NOTICE] Interrupted -- progress saved, re-run to resume.")
    finally:
        main_file.close()
        ext_file.close()

    print(f"[SUCCESS] Crawl finished. {found_count} Drive object(s) -> {output_csv}, "
          f"{external_count} external resource(s) -> {external_csv}.")

    if graph_output:
        export_graph(state.main_rows, state.ext_rows, graph_output)


def main():
    parser = argparse.ArgumentParser(description="Expansive Google Drive link-sharing enumeration crawler")
    sub = parser.add_subparsers(dest="command", required=True)

    crawl_p = sub.add_parser("crawl", help="Crawl starting from a seed file of URLs")
    crawl_p.add_argument("seed_file", help="Text file with one seed Drive URL per line")
    crawl_p.add_argument("-o", "--output", default=None, help="Drive-objects CSV path")
    crawl_p.add_argument("--external-output", default=None,
                          help="External/other-product resources CSV path")
    crawl_p.add_argument("--max-depth", type=int, default=6)
    crawl_p.add_argument("--domain", default=None,
                          help="Only continue crawling from files owned by this domain/email substring")
    crawl_p.add_argument("--delay", type=float, default=0.5)
    crawl_p.add_argument("--resume-file", default=None)
    crawl_p.add_argument("--no-binary-scan", action="store_true",
                          help="Skip downloading/scanning PDFs and Office files for links")
    crawl_p.add_argument("--include-all-external", action="store_true",
                          help="Also log generic external links (news/vendor sites, etc), "
                               "not just other Google products and cloud-storage platforms")
    crawl_p.add_argument("--check-reachability", action="store_true",
                          help="Make an unauthenticated request to each logged external/"
                               "google_other/cloud_storage link to check if it's actually "
                               "publicly accessible or bounces to a login page (requires 'requests')")
    crawl_p.add_argument("--scan-images", action="store_true",
                          help="Also download images and scan EXIF fields + QR codes for links "
                               "(requires Pillow + opencv-python; slower, opt-in)")
    crawl_p.add_argument("--graph-output", default=None,
                          help="Export the discovery graph to this path (.graphml, .gexf, or .dot; "
                               "requires networkx). Nodes = Drive objects + external resources, "
                               "edges = how each was discovered.")

    args = parser.parse_args()

    if args.command == "crawl":
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        output = args.output or f"enumerated-drive-files-{timestamp}.csv"
        external = args.external_output or f"external-resources-{timestamp}.csv"
        resume = args.resume_file or f".crawled-ids-{os.path.basename(output)}.json"
        crawl(
            seed_path=args.seed_file,
            output_csv=output,
            external_csv=external,
            max_depth=args.max_depth,
            domain_filter=args.domain,
            delay=args.delay,
            resume_path=resume,
            scan_binaries=not args.no_binary_scan,
            include_all_external=args.include_all_external,
            check_reachable=args.check_reachability,
            scan_images=args.scan_images,
            graph_output=args.graph_output,
        )


if __name__ == "__main__":
    main()
