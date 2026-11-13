---
name: app-store-connect-analytics
description: Pull first-party App Store Connect data through Apple's official App Store Connect API. Covers Analytics Reports (App Store Downloads and App Store Purchases by Source Type × Territory × day, Discovery and Engagement, Sessions) and daily Sales and Trends SALES SUMMARY reports (units, in-app purchases, refunds, developer proceeds). Requests the reports, downloads and verifies the files, and turns them into tidy CSVs. Use when the user asks for App Store Connect / ASC analytics, first-time downloads or redownloads per country, downloads or proceeds by source type (App Store search vs App referrer vs Web referrer), an organic baseline for paid campaigns, Apple proceeds or Sales and Trends numbers, or wants ASC data to join with Google Ads / GA4 / RevenueCat analyses (e.g. the google-ads-revenuecat-optimization skill).
---

# App Store Connect analytics (official API)

Apple's own numbers: downloads and purchases **by source type**, with net proceeds after
Apple's cut. Use them to split paid vs organic, and to check GA4/SDK purchase counts.

Script (persistent, standard library only, do not rewrite):
`ASC="python3 -I $HOME/.claude/skills/app-store-connect-analytics/scripts/asc_fetch.py"`.
In zsh, call it through a shell function, or run the full command each time — a command
stored in a variable is not word-split.
Reference: `references/reports.md` (report names, columns, values, limits, what's verified).

## 0. Setup gate (every run)

`$ASC check` validates `.env`, the `.p8` path and permissions, mints a token, and lists apps.
- Missing values → tell the user exactly which ones and point to README.md → "Gather the credentials". Never ask them to paste the `.p8` contents or key into chat. They put the file in `secrets/` themselves.
- 401 → wrong key ID / issuer ID / revoked key / clock. 403 → the key's role (see below).
- Never print, copy or commit the `.p8`, `.env` or tokens. Both are gitignored. Keep them that way.

## 1. One-time: request the reports (the only write)

Analytics data exists only after a **report request** is made for the app:
1. `$ASC requests` — list existing requests. Check that `stoppedDueToInactivity` is not `true`.
2. If there is no ONGOING request, ask the user first, then run `$ASC request --access ongoing`. The first report type needs an **Admin** key. The command is idempotent and does nothing if one already exists.
3. For history (Apple serves data back to Jan 1 2024), also run `$ASC request --access snapshot`. **One snapshot per month** is allowed, so don't waste it.
4. The first reports arrive about **24–48 h** later. Say so, and schedule the next step for then. After the request exists, a **Sales and Reports** or **Finance** key can read. Suggest the user swap the Admin key for one of those.

## 2. Pull

- `$ASC reports` — see the exact report names and categories (names are not hard-coded; check them here first).
- `$ASC download --report "App Store Downloads" --variant standard --granularity DAILY --access ongoing --start 2026-11-01 --out DIR`
- `$ASC download --report "App Store Purchases" --variant standard ...` — purchases, Proceeds in USD, Sales in USD.
- History: the same command with `--access snapshot` (omit `--start` to take everything).
- **Instances stay downloadable for 35 days only.** Download ONGOING data at least every few weeks into a persistent folder (e.g. `~/asc-data/<app>`). Keep the folder outside this repo, or use the gitignored `data/` folder.
- Segment URLs are pre-signed and expire after 5 min. The script downloads them right after listing, checks size and MD5, and skips files it already has.
- A day is complete **2 days** after it ends (Discovery & Engagement: 3). Leave the last 2–3 days out of any verdict.
- Sales: `$ASC sales --start D --end D --out DIR` (needs `ASC_VENDOR_NUMBER`). A 404 for a day means no sales or not published yet. Sales days are **Pacific Time**.

## 3. Summarize

Always look before filtering. Value spellings are Apple's (e.g. `First-time Download`).
The Territory encoding is not documented, so check it:
- `$ASC summarize --in DIR/app-store-downloads-standard --columns`
- `$ASC summarize --in DIR/... --distinct "Source Type"` (also `Territory`, `Download Type`, `Purchase Type`)

Recipes (matching is case-insensitive; `a|b` = either; `!=` excludes):
- US first-time downloads per day by source:
  `$ASC summarize --in DIR/app-store-downloads-standard --filter "Territory=US" --filter "Download Type=First-time Download" --group Date --pivot "Source Type" --out us_downloads.csv`
- US purchases / proceeds per day by source:
  `$ASC summarize --in DIR/app-store-purchases-standard --filter "Territory=US" --group Date,"Source Type" --sum "Purchases,Proceeds in USD" --out us_purchases.csv`
- Cohort view (purchases by when the buyer installed): `--group "App Download Date","Source Type"`.
- Net proceeds per day from Sales: `$ASC sales-summary --in DIR --country US --out us_sales.csv` (proceeds = Units × per-unit Developer Proceeds, in the proceeds currency; refunds are negative units).
- Feed into **google-ads-revenuecat-optimization** `period_compare.py --rc`:
  `--paid-shape "Purchases"` on summarize, or `--paid-shape` on sales-summary. Both write `date,total_paid,…`.

By default, overlapping instances (corrections, snapshot + ongoing) are deduplicated: the
later file wins for each row. Use `--no-dedupe` only when you know the files don't overlap.
`Paying Users` / `Unique Counts` can't be summed across rows. The script warns about this.

## 4. Interpret

- **Source type vs paid channels**: Google Ads app installs land mostly in **App referrer / Web referrer**. Apple Search Ads and organic search both land in **App Store search**. "Unavailable" covers gift cards, promo codes and MDM. So App referrer + Web referrer, compared with Google spend, is the cleanest paid read. App Store search minus Apple Search Ads installs is the organic estimate. State that this mapping is approximate (other referrers, e.g. web links or social, also count).
- **Privacy thresholds**: rows from fewer than 5 users/devices are left out, and Detailed reports also add noise. Use Standard reports for totals. Small territories and splits understate.
- **Time zones**: Sales days are PT. The analytics Date time zone is not documented (assume PT). Google Ads accounts and GA4 use their own zones. Compare weekly windows, not single days.
- **Cross-checks**: App Store Purchases `Purchases` vs Sales IAP units vs GA4 `purchase` events per day should roughly agree. A persistent gap means missing SDK events or double-counting.

## Output

Lead with the answer. Give one table (per period or per source) with numbers the user can
check against the App Store Connect UI. State the caveats that change the decision:
incomplete recent days, privacy thresholds, source-type mapping, time zone.
