# Security Health Check

## What it does
Security Health Check looks at a business's website address and email setup, and tells the owner in plain words how safe they are. It gives a score from 0 to 100, a letter grade, and a short list of the most important things to fix first.

## The problem it solves
Many small businesses have no idea if scammers could pretend to be them by email, or if their email is likely to land in spam. These problems are invisible until something goes wrong, and most owners cannot judge them on their own.

## How it helps people
- Shows what is wrong without confusing technical language
- Puts the biggest problems first, so owners know where to start
- Points each problem to the PIXEL7 MEDIA service that can fix it
- Only reads public information, so it never touches the business's own computers or files

## What it checks today
- Whether the business can receive email
- Whether the business has a list of who may send email in its name (SPF)
- Whether fake emails pretending to be the business are blocked (DMARC)
- Whether emails are signed to prove they are real (DKIM, best effort)

## Coming next
Website safety checks, ownership confirmation before scanning, a questionnaire about Wi-Fi, devices and backups, and easy-to-read reports written with AI help.

---

## For developers

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest                         # run the tests
uvicorn app.main:app --reload  # start the server
```

Try it: `POST http://127.0.0.1:8000/api/scan/email` with `{"domain": "example.com"}`.
Interactive docs: `http://127.0.0.1:8000/docs`.

```
app/
  main.py           web server and endpoints
  domain.py         cleans and checks the domain a user types
  dns_client.py     DNS lookups (easy to fake in tests)
  scoring.py        fixed scoring rules (no AI)
  models.py         result shapes
  scanners/
    email_dns.py    MX, SPF, DKIM, DMARC checks
tests/              44 tests, none need the internet
```
