# App Store Connect reports — reference

Verified against Apple's docs on 2026-11-13. Items marked *(unverified)* were not in the
docs: confirm them with `asc_fetch.py reports` / `summarize --columns` on real data, then
update this file.

## Analytics Reports API

Flow: `POST /v1/analyticsReportRequests` → `GET /v1/apps/{id}/analyticsReportRequests` →
`GET /v1/analyticsReportRequests/{id}/reports` → `GET /v1/analyticsReports/{id}/instances`
(`filter[granularity]=DAILY|WEEKLY|MONTHLY`) → `GET /v1/analyticsReportInstances/{id}/segments`
→ download each segment `url` (pre-signed S3, valid **5 minutes**, no JWT; gzip TSV).

- Request body: `{"data":{"type":"analyticsReportRequests","attributes":{"accessType":"ONGOING"},"relationships":{"app":{"data":{"type":"apps","id":"<APP_ID>"}}}}}`
- `accessType`: `ONGOING` (daily, weekly and monthly reports from then on, first one about 24–48 h later) or `ONE_TIME_SNAPSHOT` (all available history; **one per month**).
- Request attribute `stoppedDueToInactivity` (bool): if true, create a new ONGOING request.
- Instances are kept **35 days**. A day's data is complete **2 days** after it ends.
- Segment attributes: `url`, `checksum` (32-hex, treated as MD5 — *algorithm unverified*), `sizeInBytes`.
- Roles: the **first** request of a report type needs **Admin**. Downloading works with Admin, **Sales and Reports**, or **Finance**.
- *(unverified)* server-side `filter[category]`, `filter[name]`, `filter[processingDate]`: the script filters on the client instead. Category enum strings other than `PERFORMANCE` are unverified.
- *(unverified)* the exact API `name` strings, e.g. "App Store Downloads Standard". The script matches by substring plus `--variant`.

Docs: https://developer.apple.com/help/app-store-connect-analytics/overview/analytics-reports-api/ ·
https://developer.apple.com/tutorials/data/documentation/analytics-reports.md ·
https://developer.apple.com/tutorials/data/documentation/appstoreconnectapi/post-v1-analyticsreportrequests.md ·
https://developer.apple.com/tutorials/data/documentation/appstoreconnectapi/get-v1-analyticsreportinstances-_id_-segments.md

### App Store commerce reports
App Store Downloads · App Store Pre-orders · App Store Purchases · App Store Subscription State · App Store Subscription Event

### App Store Downloads (standard / detailed)
https://developer.apple.com/tutorials/data/documentation/analytics-reports/app-download.md

Standard columns: `Date, App Name, App Apple Identifier, Download Type, App Version, Device,
Platform Version, Source Type, Page Type, Pre-Order, Territory, Counts`. Detailed adds
`Source Info, Campaign (from 2024-11-19), Page Title`. Daily for both variants. Weekly and monthly for detailed only.
History from 2024-01-01.

- Download Type: `First-time Download`, `Redownload`, `Manual update`, `Auto-update`, `Restore`
- Source Type: `App Store search`, `App Store browse`, `App referrer`, `Web referrer`, `App Clip`, `Unavailable`, `Institutional purchase`
- Page Type: `Product page`, `In-App event`, `Store sheet`, `No Page`

### App Store Purchases (standard / detailed)
https://developer.apple.com/tutorials/data/documentation/analytics-reports/app-store-purchase.md

Columns: `Date, App Name, App Apple Identifier, Purchase Type, Content Name, Content Apple
Identifier, Payment Method, Device, Platform Version, Source Type, [Source Info], [Campaign],
Page Type, [Page Title], App Download Date, Pre-Order, Territory, Purchases, Proceeds in USD,
Sales in USD, Paying Users`. The `[ ]` columns are detailed only.

- `Purchases`: count. Negative values are refunds. `Proceeds in USD`: estimated, after taxes and Apple's commission. `Sales in USD`: estimated customer spend. `Paying Users`: **not summable**.
- Purchase Type: `App purchase`, `In-app purchases`. Source Type adds `In-store purchase`.
- `App Download Date` → cohort analysis (purchases by install date and source).

### Privacy
https://developer.apple.com/tutorials/data/documentation/analytics-reports/privacy.md

Values from fewer than 5 users or devices are left out. Detailed reports also add a small
amount of noise. Use Standard for totals.

### Unverified
- Territory encoding (ISO `US` vs `United States`). Check it with `summarize --distinct Territory`.
- The analytics Date time zone. Assume PT, like Sales.

## Sales and Trends — `GET /v1/salesReports`
https://developer.apple.com/tutorials/data/documentation/appstoreconnectapi/get-v1-salesreports.md

- Params: `filter[frequency]=DAILY`, `filter[reportType]=SALES`, `filter[reportSubType]=SUMMARY`, `filter[vendorNumber]`, `filter[reportDate]=YYYY-MM-DD`, `filter[version]`. The API table lists SALES/SUMMARY as `1_0`, while the column reference page says "Version 1_3". The script tries 1_0 first, then 1_1 and 1_3 on a version error.
- Response: gzip TSV (`Accept: application/a-gzip`). A day with no data returns 404 *(expected; unverified)*.
- Days are **Pacific Time** (12:00 a.m.–11:59 p.m. PT).
- `INSTALLS` reports have been deprecated since 2026-11-04. Don't build on them.
- Columns include `Product Type Identifier, Units, Developer Proceeds, Begin Date, End Date, Customer Currency, Country Code, Currency of Proceeds, Apple Identifier, Customer Price, …`. `Developer Proceeds` is **per unit**, so total proceeds = Units × Developer Proceeds.
- Product type groups used by `sales-summary`: `1*` app downloads, `3*` redownloads, `7*` updates, `IA*`/`FI*` in-app purchases (IA1 purchase, IA9 non-renewing, IAY auto-renewable, IAC free subscription).

## JWT
https://developer.apple.com/tutorials/data/documentation/appstoreconnectapi/generating-tokens-for-api-requests.md

The header is `{"alg":"ES256","kid":<KEY_ID>,"typ":"JWT"}`. For a team key the payload is
`{"iss":<ISSUER_ID>,"iat","exp","aud":"appstoreconnect-v1"}`. For an individual key it uses
`"sub":"user"` instead of `iss`. Lifetime is at most 20 minutes for these endpoints (the script
uses 19). The signature is raw r‖s (64 bytes). OpenSSL outputs DER, so the script converts it.
