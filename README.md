# app-store-connect-analytics

A Claude Code skill that pulls **first-party App Store Connect data** through Apple's official
App Store Connect API:

- **Analytics Reports**: App Store Downloads and App Store Purchases per day, broken down by
  Source Type (App Store search / browse, App referrer, Web referrer, …), Territory,
  Download Type and more. It also covers Discovery and Engagement, Sessions and other report types.
- **Sales and Trends**: daily SALES SUMMARY reports with units, in-app purchases, refunds and
  developer proceeds.

It writes tidy CSVs. With `--paid-shape`, the output plugs straight into
`google-ads-revenuecat-optimization/scripts/period_compare.py --rc`.

Standard library Python 3.9+. Signing uses `cryptography` if installed, otherwise the
`openssl` CLI (built into macOS).

## Install

```bash
git clone <this repo> ~/.claude/skills/app-store-connect-analytics
cp ~/.claude/skills/app-store-connect-analytics/.env.example ~/.claude/skills/app-store-connect-analytics/.env
```

## What stays out of git

| File | Purpose | Committed? |
|---|---|---|
| `.env` | key ID, issuer ID, app ID, vendor number | **no** (gitignored) |
| `secrets/AuthKey_<KEY_ID>.p8` | API private key | **no** (`secrets/*` and `*.p8` are gitignored) |
| `data/`, `*.gz`, `*.tsv`, `*.csv` | downloaded reports, outputs | **no** |
| `.env.example`, `secrets/README.md` | templates | yes |

`asc_fetch.py check` warns if the `.p8` can be read by other users or is tracked by git.

## Gather the credentials

You need four things. Only the Account Holder or an Admin can create API keys.

### 1. Turn on API access (once per account)
App Store Connect → **Users and Access** → **Integrations** tab → **App Store Connect API**.
If you see **Request Access**, the Account Holder has to click it and accept the terms first.

### 2. Create a Team API key → `ASC_KEY_ID`, `ASC_ISSUER_ID`, `.p8`
1. On the same page, open **Team Keys** and click **Generate API Key** (or **+**).
2. Name it (e.g. `claude-analytics`). For **Access**, choose:
   - **Admin** for the very first run. Apple requires Admin to *create* the first Analytics
     report request for a report type.
   - After the reports exist, create a second key with **Sales and Reports** (or **Finance**),
     put it in `.env`, and **revoke the Admin key**. Reading reports doesn't need Admin.
3. **Key ID**: shown in the key's row. → `ASC_KEY_ID`
4. **Issuer ID**: shown above the keys table, with a copy button. → `ASC_ISSUER_ID`
5. **Download API Key** gives `AuthKey_<KEY_ID>.p8`. **Apple lets you download it only once.**
   Move it into place and lock it down:
   ```bash
   mv ~/Downloads/AuthKey_XXXXXXXXXX.p8 ~/.claude/skills/app-store-connect-analytics/secrets/
   chmod 600 ~/.claude/skills/app-store-connect-analytics/secrets/AuthKey_*.p8
   ```
   Keep a backup in your password manager, not in the repo.

*Individual key alternative*: **Users and Access** → your user → **Individual API Key**. It
inherits your own roles. Set `ASC_KEY_TYPE=individual` and leave `ASC_ISSUER_ID` empty.
Prefer a team key: it can be given exactly one role and revoked without touching your user.

### 3. App Apple ID → `ASC_APP_ID`
App Store Connect → **Apps** → your app → **App Information** → **General Information** →
**Apple ID** (numeric). Or run `asc_fetch.py apps` once the key works.

### 4. Vendor number → `ASC_VENDOR_NUMBER` (only for Sales reports)
App Store Connect → **Payments and Financial Reports**. The vendor number is at the top
left, next to your legal entity name. You can also find it under **Sales and Trends** →
**Reports**.

## First run

```bash
ASC="python3 -I ~/.claude/skills/app-store-connect-analytics/scripts/asc_fetch.py"
$ASC selftest                      # signing works on this machine (no network)
$ASC check                         # config + token + list of apps
$ASC request --access ongoing      # once, with the Admin key → daily reports start in ~24–48 h
$ASC request --access snapshot     # optional history back to 2024-01-01 (one per month)
# 1–2 days later:
$ASC reports
$ASC download --report "App Store Downloads" --out ~/asc-data/passport
$ASC summarize --in ~/asc-data/passport/app-store-downloads-standard --distinct "Source Type"
```

In zsh, `$ASC` isn't split into words, so run the full `python3 -I …` command or define a
shell function instead.

Instances expire after **35 days**. Download at least every few weeks, or let the skill run
on a schedule.

## Safety

Every command is read-only except `request`, which creates an analytics report request. It
is idempotent and is not destructive. Tokens last 19 minutes and are never written to disk.
