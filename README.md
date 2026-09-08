LinkRunner (Python rewrite, expanded coverage)
================================================

Enumerates everything reachable by crawling outward from "anyone with the
link" Google Drive seed(s):

  - Docs/Sheets/Slides/Forms content is exported and scanned for further
    Drive links.
  - Folders (including Shared Drive roots) are listed and their children
    are queued, recursively.
  - PDFs and Office files (docx/xlsx/pptx) are downloaded and scanned for
    embedded links (PDF text + link annotations; OOXML zip internals).
  - Anything discovered that ISN'T a crawlable Drive object -- other
    Google products (Sites, Colab, Forms responses, Jamboard, Maps,
    Groups, Calendar) or fully external URLs -- is logged to a separate
    "external resources" CSV as a boundary/finding, since the tool has
    no API access to crawl into those.

Intended for AUTHORIZED security assessments / internal Drive-hygiene
audits only. You need to already possess (or otherwise be authorized to
use) every seed link -- this tool does not bypass any access control, it
only follows references between resources that are already reachable.

Usage:
    python linkrunner.py crawl seeds.txt -o results.csv
    
Auth:
    First run opens a browser for Google OAuth consent (installed-app
    flow) using credentials.json in the working directory, or drops in a
    service_account.json if present. See README.md.


    # One seed URL per line. Lines starting with # are ignored.
# https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUvWxYz1234567890/edit
# https://docs.google.com/spreadsheets/d/1AbCdEfGhIjKlMnOpQrStUvWxYz1234567890/edit
