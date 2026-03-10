<a id="kql-for-email-security-beginner-series" name="kql-for-email-security-beginner-series"></a>
# KQL for Email Security — Beginner Series

Learn to hunt threats in Microsoft 365 email using Kusto Query Languag (KQL)

**Where to run these queries:** [Microsoft Defender portal](https://security.microsoft.com) → Investigation & response → Hunting → Advanced hunting

### Sample Tables
| Table | What It Tells You |
|-------|------------------|
| `EmailEvents` | Every email that touched your org |
| `EmailAttachmentInfo` | Files attached to those emails |
| `EmailUrlInfo` | Links embedded in emails |
| `UrlClickEvents` | Who clicked what, and when |
| `EmailPostDeliveryEvents` | What happened after delivery (ZAP, moves, deletes) |
| `IdentityLogonEvents` | User sign-ins and authentication |
| `CloudAppEvents` | User actions in cloud apps (Exchange, SharePoint, etc.) |

<br>

<a id="toc" name="toc"></a>
# Table of Contents

  - [Table Relationships Quick Reference](#table-relationships-quick-reference)
  - [getschema](#getschema)
  - [print](#print)
  - [comments ( // )](#comments---)
  - [pipe ( | )](#pipe---)
  - [spacing](#spacing)
  - [order matters](#order-matters)
  - [search](#search)
  - [take / limit / sample](#take--limit--sample)
  - [where](#where)
  - [== / != (equality operators)](#---equality-operators)
  - [and / or / in](#and--or--in)
  - [tilde ( ~ )](#tilde---)
  - [project](#project)
  - [project-away / project-reorder](#project-away--project-reorder)
  - [distinct](#distinct)
  - [sort by](#sort-by)
  - [contains / has / startswith / endswith](#contains--has--startswith--endswith)
  - [negation ( ! )](#negation---)
  - [count](#count)
  - [\>, \<, \>=, \<= (numeric comparisons)](#----numeric-comparisons)
  - [ago()](#ago)
  - [between / datetime](#between--datetime)
  - [Time Formats](#time-formats)
  - [now()](#now)
  - [top](#top)
  - [extend](#extend)
  - [Live Scenario: EmailAttachmentInfo](#live-scenario-emailattachmentinfo)
  - [Live Scenario: EmailEvents](#live-scenario-emailevents)
  - [Live Scenario: CloudAppEvents](#live-scenario-cloudappevents)
  - [Live Scenario: UrlClickEvents](#live-scenario-urlclickevents)
  - [Live Scenario: EmailPostDeliveryEvents](#live-scenario-emailpostdeliveryevents)
  - [Common Gotchas \& Tips](#common-gotchas--tips)
---

<a id="table-relationships-quick-reference" name="table-relationships-quick-reference"></a>
## Table Relationships Quick Reference

Understanding how tables relate is critical for effective hunting:

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
┌─────────────────┐     NetworkMessageId      ┌─────────────────────┐
│   EmailEvents   │◄──────────────────────────│ EmailAttachmentInfo │
│                 │                           └─────────────────────┘
│  (Core email    │     NetworkMessageId      ┌─────────────────────┐
│   metadata)     │◄──────────────────────────│    EmailUrlInfo     │
│                 │                           └─────────────────────┘
│                 │     NetworkMessageId      ┌─────────────────────────┐
│                 │◄──────────────────────────│ EmailPostDeliveryEvents │
└─────────────────┘                           └─────────────────────────┘
        │
        │ RecipientEmailAddress / AccountUpn
        ▼
┌─────────────────────┐         AccountUpn / AccountObjectId         ┌──────────────────┐
│ IdentityLogonEvents │◄─────────────────────────────────────────────│  CloudAppEvents  │
│ (Sign-ins)          │                                              │ (User actions)   │
└─────────────────────┘                                              └──────────────────┘
</pre>

**Key Join Fields:**
- `NetworkMessageId` — Links all email-related tables
- `AccountUpn` / `RecipientEmailAddress` — Links email to identity tables
- `AccountObjectId` — Links identity events to cloud app events

[back to top](#kql-for-email-security-beginner-series)

---

<a id="getschema" name="getschema"></a>
## getschema

- Displays column names and data types for tables.
- Essential for discovering what data is available.

**Examples**

```kusto
EmailEvents | getschema
```

```kusto
IdentityLogonEvents | getschema
```

```kusto
CloudAppEvents | getschema
```

```kusto
EmailAttachmentInfo | getschema
```

```kusto
EmailUrlInfo | getschema
```

```kusto
UrlClickEvents | getschema
```

```kusto
EmailPostDeliveryEvents | getschema
```

```kusto
AlertInfo | getschema
```

```kusto
AlertEvidence | getschema
```

```kusto
EntraSignInEvents | getschema
```

```kusto
EntraSpnSignInEvents | getschema
```

```kusto
IdentityInfo | getschema
```

```kusto
MessageEvents | getschema
```

```kusto
MessagePostDeliveryEvents | getschema
```

```kusto
MessageUrlInfo | getschema
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="print" name="print"></a>
## print

- Use `print` to test expressions without querying tables.
- Great for learning time functions, string manipulation, etc.
- 
**Examples**

```kusto
// Test time expressions
print CurrentTime = now(), OneWeekAgo = ago(7d), OneDayAgo = ago(1d)
```

```kusto
// Test string functions
print 
    Original = "user@CONTOSO.com",
    Lower = tolower("user@CONTOSO.com"),
    Upper = toupper("user@contoso.com")
```

```kusto
// Test math expressions
print 
    BytesToKB = 1048576 / 1024,
    BytesToMB = 1048576 / 1024 / 1024
```

```kusto
// Test conditional expressions
print
    IsHighSeverity = iff("High" == "High", true, false),
    SeverityLabel = case(
        "High" == "High", "🔴 High",
        "High" == "Medium", "🟡 Medium",
        "🟢 Low"
    )
```

```kusto
// Test strcat — useful for building display strings
print
    AlertSummary  = strcat("[ALERT] ", "Suspicious sign-in", " — Severity: High"),
    BehaviorLabel = strcat("User: ", "bob@contoso.com", " | Action: ", "LateralMovement")
```

```kusto
// Test dynamic arrays — used in AttackTechniques and ThreatTypes
print
    Techniques   = dynamic(["T1078", "T1059", "T1003"]),
    FirstTech    = tostring(dynamic(["T1078", "T1059"])[0]),
    TechCount    = array_length(dynamic(["T1078", "T1059", "T1003"]))
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="comments" name="comments"></a>
## comments ( // )

- Use `//` to add inline comments to queries.
- Helps document your logic for future reference.

**Examples**

```kusto
// Show last 10 email events
EmailEvents
| take 10
```

```kusto
// Look at recent sign-ins
IdentityLogonEvents
| where Timestamp > ago(1d)
// | where Application == "Microsoft SharePoint Online"  // Uncomment to filter by app
| take 10
```

```kusto
// Browse recent Entra sign-in events
EntraSignInEvents
| where Timestamp > ago(1d)
// | where ErrorCode != 0  // Uncomment to filter failures only
| take 10
```

```kusto
// Browse recent security alerts
AlertInfo
| where Timestamp > ago(1d)
// | where Severity == "High"  // Uncomment to filter by severity
| take 10
```

```kusto
// Browse Teams message events
MessageEvents
| take 10
// MessageEvents = Teams messages scanned by Defender for Office 365
```

```kusto
// Browse identity info for a user
IdentityInfo
// | where AccountUpn =~ "user@contoso.com"  // Uncomment and set UPN
| take 10
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="pipe" name="pipe"></a>
## pipe ( | )

- The pipe passes data from one operation to the next.
- Read queries top-to-bottom, left-to-right.

**How pipe works**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
EmailEvents                               ← Start: All rows from table
      │
      ▼
| where Timestamp > ago(7d)               ← Filter: Keep only last 7 days
      │
      ▼
| where SenderFromDomain has "x"          ← Filter: Keep matching domains
      │
      ▼
| project Subject, SenderFromAddress      ← Select: Keep only these columns
      │
      ▼
| take 10                                 ← Limit: Return first 10 rows
</pre>

**Examples**

```kusto
EmailEvents
| where SenderFromDomain == "gmail.com"
| project Subject, SenderFromAddress, RecipientEmailAddress
```

```kusto
IdentityLogonEvents
| where Timestamp > ago(1d)
// | where Application has "Office"
| project Timestamp, AccountUpn, Application, Location
```

```kusto
CloudAppEvents
| where ActionType == "FileDownloaded"
| take 5
| project Timestamp, AccountDisplayName, ActionType, Application
```

```kusto
// Sign-in failures piped to clean output
EntraSignInEvents
| where Timestamp > ago(1d)
| where ErrorCode != 0
| project Timestamp, AccountUpn, Application, IPAddress, Country, ErrorCode
```

```kusto
// Alert evidence filtered to user entities only
AlertEvidence
| where Timestamp > ago(7d)
| where EntityType == "User"
| project Timestamp, AlertId, AccountUpn, EvidenceRole, RemoteIP
```

```kusto
// Teams message URLs — browse what URLs are being sent
MessageUrlInfo
| where Timestamp > ago(7d)
| project Timestamp, TeamsMessageId, Url, UrlDomain
| take 20
```

```kusto
// EmailUrlInfo — URLs piped to distinct domains
EmailUrlInfo
| where Timestamp > ago(7d)
| distinct UrlDomain
| sort by UrlDomain asc
```

```kusto
// UrlClickEvents — blocked clicks piped to clean output
UrlClickEvents
| where Timestamp > ago(7d)
| where ActionType == "ClickBlocked"
| project Timestamp, AccountUpn, Url, IsClickedThrough
```

```kusto
// EmailPostDeliveryEvents — ZAP actions piped to summary
EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| where ActionType has "ZAP"
| project Timestamp, NetworkMessageId, ActionType, DeliveryLocation
```

```kusto
// EmailAttachmentInfo — suspicious extensions piped to count
EmailAttachmentInfo
| where Timestamp > ago(7d)
| where FileExtension in (".exe", ".ps1", ".vbs", ".bat")
| project Timestamp, SenderFromAddress, FileName, FileExtension
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="spacing" name="spacing"></a>
## spacing

- KQL ignores extra spaces and newlines.
- Indentation improves readability for complex queries.

**Examples**

```kusto
EmailEvents
| where
    SenderFromDomain has "gmail"
    and DeliveryLocation has "Inbox"
| project Subject,
    RecipientEmailAddress, NetworkMessageId
| take                                                                                                                        5
```

```kusto
// Spacing makes multi-condition filters readable
AlertInfo
| where
    Timestamp > ago(7d)
    and Severity == "High"
    and ServiceSource has "Defender"
| project Timestamp,
    AlertId, Title, Severity, Category
| take                                                 10
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="order-matters" name="order-matters"></a>
## order matters

KQL executes each pipe stage **left to right, top to bottom** — the output of one stage becomes the input of the next. That means the earlier you reduce the dataset, the less work every later stage has to do.

**Mental Model:**
1. **Time filter first** — shrinks the dataset at the source using the built-in time index
2. **Column filters next** — narrow rows on indexed/selective columns
3. **Shape last** — `project`, `extend`, `distinct`, `sort` operate on what survived

Get wide data narrow *before* doing expensive operations on it.

---

**Scenario 1: find high-severity MDO alerts from the last 7 days**

```kusto
// Step 1 — Start with the table
// Every query starts here. No filters yet — this would return ALL data.
AlertInfo
```

```kusto
// Step 2 — Add the time filter FIRST
// Timestamp is indexed. This one filter can eliminate millions of rows before anything else runs.
// Always your first where clause.
AlertInfo
| where Timestamp > ago(7d)
```

```kusto
// Step 3 — Add a column filter SECOND
// Now we narrow to just High severity rows — but only from the 7-day window we already scoped.
// The engine never touches older rows at all.
AlertInfo
| where Timestamp > ago(7d)
| where Severity == "High"
```

```kusto
// Step 4 — Add a second column filter before any shaping
// Still filtering, not yet reshaping. More rows eliminated cheaply.
AlertInfo
| where Timestamp > ago(7d)
| where Severity == "High"
| where ServiceSource == "AAD Identity Protection"
```

```kusto
// Step 5 — Shape the output with project
// project runs last, on only the rows that survived all filters.
// If project ran first, it would process every row in the table.
AlertInfo
| where Timestamp > ago(7d)
| where Severity == "High"
| where ServiceSource == "AAD Identity Protection"
| project Timestamp, Title, Category, ServiceSource
```

```kusto
// Step 6 — Final query: sort and limit at the very end
// sort and take are the most expensive per-row operations.
// Running them on 20 rows is trivial. Running them on millions is not.
AlertInfo
| where Timestamp > ago(7d)
| where Severity == "High"
| where ServiceSource == "AAD Identity Protection"
| project Timestamp, Title, Category, ServiceSource
| sort by Timestamp desc
| take 20
```

**What happens if you get the order wrong?**

`project` before `where` is the most common mistake. Here's why it hurts:

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
┌─────────────────────────────┬──────────────────────────────┐
│ Inefficient order:          │ Efficient order:             │
├─────────────────────────────┼──────────────────────────────┤
│ AlertInfo                   │ AlertInfo                    │
│ | project Title, Severity   │ | where Timestamp > ago(7d)  │
│ | where Timestamp > ago(7d) │ | where Severity == "High"   │
│ | where Severity == "High"  │ | project Title, Severity    │
└─────────────────────────────┴──────────────────────────────┘
</pre>

In the inefficient version, `project` reshapes **every row in the table** before the time filter even runs.  
In the efficient version, the time filter eliminates the vast majority of rows before `project` ever sees them.

---

**Scenario 2: finding inbound emails with attachments from external senders**

```kusto
// Step 1 — Start with the table
// EmailEvents holds every email event in the tenant — potentially millions of rows.
EmailEvents
```

```kusto
// Step 2 — Time filter first (always)
// The Timestamp index makes this the cheapest possible filter.
// Everything outside 7 days is gone before any other work happens.
EmailEvents
| where Timestamp > ago(7d)
```

```kusto
// Step 3 — Filter by direction
// "Inbound" likely cuts the dataset roughly in half.
// Still just a row filter — no shaping yet.
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound"
```

```kusto
// Step 4 — Filter to emails that actually have attachments
// AttachmentCount > 0 eliminates the majority of inbound email.
// We're now working with a much smaller set before doing anything expensive.
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound"
| where AttachmentCount > 0
```

```kusto
// Step 5 — extend adds a derived column AFTER all row filtering
// If it ran before the filters, it would compute on the entire table.
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound"
| where AttachmentCount > 0
| extend AttachmentRisk = case(
    AttachmentCount > 5, "High",
    AttachmentCount > 1, "Medium",
    "Low")
```

```kusto
// Step 6 — Final query: project and sort last
// project selects only the columns we need — on the smallest possible row set.
// sort runs last, on already-filtered, already-shaped output.
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound"
| where AttachmentCount > 0
| extend AttachmentRisk = case(
    AttachmentCount > 5, "High",
    AttachmentCount > 1, "Medium",
    "Low")
| project Timestamp, AttachmentRisk, RecipientEmailAddress, Subject, AttachmentCount
| sort by Timestamp desc
```

**The rule of thumb:**

| Stage | What to do | Why |
|---|---|---|
| 1st `where` | `Timestamp > ago(Xd)` | Uses the time index — free row elimination |
| 2nd `where` | Most selective column filter | Eliminates the most rows cheapest |
| 3rd+ `where` | Additional column filters | Keep narrowing before any computation |
| `distinct` | Deduplicate | After filters, before sort — never sort duplicates you're about to drop |
| `extend` | Computed/derived columns | Only compute on rows that survived |
| `project` | Shape the output | Runs on the smallest possible set |
| `sort` / `take` | Ordering and limits | Always last — most expensive per row |

**Examples**

```kusto
// Efficient — filter before projection
EmailEvents
| where SenderFromDomain == "gmail.com"
| project Timestamp, SenderFromAddress, Subject
```

```kusto
// Inefficient — projection before filtering
EmailEvents
// | where Timestamp >= ago(7d)
| project SenderFromDomain, Subject
| where SenderFromDomain == "gmail.com"
```

```kusto
// Efficient — distinct then sort (dedupe before sort)
EmailEvents
| distinct SenderFromDomain
| sort by SenderFromDomain desc
| take 10
```

```kusto
// Less efficient — sort everything first, then dedupe
EmailEvents
| sort by SenderFromDomain
| distinct SenderFromDomain
| take 10
```

```kusto
// Efficient — filter before projection
IdentityLogonEvents
| where Timestamp > ago(1d)
| where Application == "Microsoft 365"
| project Timestamp, AccountUpn, Location, Application
```

```kusto
// Inefficient — expensive extend before filtering
// extend computes strcat for every row
// many of those rows get discarded by the where clauses after
IdentityLogonEvents
| extend Geo = strcat(Location, "-", AccountUpn)
| where Timestamp > ago(1d)
| where Application == "Microsoft 365"
| project Timestamp, AccountUpn, Location, Geo
```

```kusto
// Efficient — time filter first on Entra sign-ins
EntraSignInEvents
| where Timestamp > ago(1d)   // ← filter early
| where ErrorCode != 0
| project Timestamp, AccountUpn, Application, IPAddress, ErrorCode
```

```kusto
// Inefficient — project before filter wastes work
// all rows flow through project before the ErrorCode filter
EntraSignInEvents
| project Timestamp, AccountUpn, Application, IPAddress, ErrorCode
| where Timestamp > ago(1d)
| where ErrorCode != 0
```

```kusto
// Efficient — filter alerts before extending labels
AlertInfo
// | where Timestamp > ago(7d)           // ← filter first
| where Severity == "High"            // ← second filter
| extend SevTag = strcat("[", Severity, "] ", Title)  // extend after
| project Timestamp, SevTag, Category, ServiceSource
```

```kusto
// Efficient — filter before distinct, distinct before count
IdentityInfo
| where IsAccountEnabled == true   // ← filter before distinct
| distinct Department
| count
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="search" name="search"></a>
## search

- Full-text search across all columns.
- Use for quick exploration, not production queries.

**Examples**

```kusto
search "facebook"
```

```kusto
// Search within specific tables
search in (IdentityLogonEvents, CloudAppEvents) "failed"
```

```kusto
search in (EmailEvents, CloudAppEvents)
 "facebook"
| where Timestamp > ago(24h)
```

```kusto
search in (CloudAppEvents)
 "groupon"
| where Timestamp > ago(1d)
| take 100
```

```kusto
// Search alert tables for a specific MITRE technique
search in (AlertInfo, AlertEvidence) "T1078"
| where Timestamp > ago(7d)
```

```kusto
// Search identity tables for a suspicious IP address
search in (EntraSignInEvents, IdentityLogonEvents) "185.220.101.1"
| where Timestamp > ago(7d)
```

```kusto
// Search Teams message tables for malicious content
search in (MessageEvents, MessageUrlInfo) "malware"
| where Timestamp > ago(7d)
```

```kusto
// Search EmailUrlInfo for a suspicious domain
search in (EmailUrlInfo) "malware-site.com"
| where Timestamp > ago(30d)
```

```kusto
// Search UrlClickEvents for a blocked action
search in (UrlClickEvents) "ClickBlocked"
| where Timestamp > ago(7d)
```

```kusto
// Search EmailAttachmentInfo and EmailUrlInfo together
search in (EmailAttachmentInfo, EmailUrlInfo) "phish"
| where Timestamp > ago(7d)
```

```kusto
// Search EmailPostDeliveryEvents for ZAP activity
search in (EmailPostDeliveryEvents) "ZAP"
| where Timestamp > ago(7d)
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="take-limit-sample" name="take-limit-sample"></a>
## take / limit / sample

- `take` / `limit` - Returns first N rows (same behavior)
- `sample` - Returns N random rows

**Difference: take vs sample**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
              EmailEvents (1000 rows)
                    │
        ┌───────────┴───────────┐
        │                       │
   | take 3                | sample 3
        │                       │
        ▼                       ▼
┌─────────────┐         ┌─────────────┐
│ Row 1       │         │ Row 847     │  ← random
│ Row 2       │         │ Row 123     │  ← random
│ Row 3       │         │ Row 592     │  ← random
└─────────────┘         └─────────────┘
  First 3 rows           Random 3 rows
</pre>

**Examples**

```kusto
EmailEvents
| take 25
```

```kusto
IdentityLogonEvents | limit 5
```

```kusto
// Sample gives random rows - great for exploring data variety
CloudAppEvents | sample 1
```

```kusto
EmailAttachmentInfo | take 10
```

```kusto
EmailUrlInfo | take 10
```

```kusto
UrlClickEvents | take 10
```

```kusto
EmailPostDeliveryEvents 
| where Timestamp >= ago(24h)
// | take 10
```

```kusto
AlertInfo | take 10
```

```kusto
AlertEvidence | take 10
```

```kusto
EntraSignInEvents
| where Timestamp > ago(1d)
| take 10
```

```kusto
IdentityInfo | take 10
```

```kusto
MessageEvents | take 10
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="where" name="where"></a>
## where

- Filters rows based on conditions.
- Only rows where the condition is `true` pass through.

**How `where` works**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
Before: EmailEvents (all rows)
┌──────────────┬─────────────────┬───────────────┐
│ Subject      │ SenderDomain    │ Timestamp     │
├──────────────┼─────────────────┼───────────────┤
│ Invoice      │ external.com    │ 2024-01-15    │   passes
│ Meeting      │ contoso.com     │ 2024-01-15    │   filtered
│ Payment Due  │ external.com    │ 2024-01-14    │   passes
│ Hello        │ contoso.com     │ 2024-01-14    │   filtered
└──────────────┴─────────────────┴───────────────┘
                      │
    | where SenderDomain != "contoso.com"
                      │
                      ▼
After: Only external emails
┌──────────────┬─────────────────┬───────────────┐
│ Invoice      │ external.com    │ 2024-01-15    │
│ Payment Due  │ external.com    │ 2024-01-14    │
└──────────────┴─────────────────┴───────────────┘
</pre>

**Examples**

```kusto
EmailEvents
| where Timestamp >= ago(1d)
| where EmailDirection == "Inbound"
| where SenderFromDomain == "yahoo.com"
| take 10
```

```kusto
// Filter sign-ins by result
IdentityLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonFailed"
| take 10
```

```kusto
// Filter cloud events by action
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType has "SoftDelete"
| take 10
```

```kusto
// Find attachments with specific threat detections
EmailAttachmentInfo
| where Timestamp > ago(1d)
// | where isnotempty(ThreatTypes)
| project Timestamp, SenderFromAddress, RecipientEmailAddress, FileName, FileType, ThreatTypes, ThreatNames
| take 20
```

```kusto
// Find emails containing URLs from specific domains
EmailUrlInfo
| where Timestamp > ago(7d)
| where UrlDomain has "twitter" or UrlDomain has "facebook"
| project Timestamp, NetworkMessageId, Url, UrlDomain, UrlLocation
| take 20
```

```kusto
EmailUrlInfo
// | where Timestamp > ago(1d)
| where UrlLocation == "Attachment"
// | where Url contains "facebook"
| project Timestamp, NetworkMessageId, Url, UrlDomain, UrlLocation
| take 20
```

```kusto
EmailUrlInfo
| distinct UrlLocation
```

```kusto
UrlClickEvents
| where Timestamp > ago(30d)
// | where ActionType == "ClickBlocked"
// | project Timestamp, AccountUpn, Url, ActionType, ThreatTypes, Workload
```

```kusto
UrlClickEvents
| where Timestamp > ago(30d)
// | where IsClickedThrough == true
| project Timestamp, AccountUpn, Url, ThreatTypes, Workload
| take 20
```

```kusto
EmailPostDeliveryEvents
// | where Timestamp > ago(30d)
| where ActionType has "ZAP"
| project Timestamp, NetworkMessageId, RecipientEmailAddress, ActionType, ActionTrigger, ActionResult, DeliveryLocation
| take 20
```

```kusto
// Find manual remediation actions by admins
EmailPostDeliveryEvents
| where Timestamp > ago(30d)
| where ActionType == "Manual Remediation"
| project Timestamp, NetworkMessageId, RecipientEmailAddress, Action, ActionTrigger, ActionResult
| take 20
```

```kusto
// Filter Entra sign-in failures
EntraSignInEvents
| where Timestamp > ago(7d)
| where ErrorCode != 0
| project Timestamp, AccountUpn, Application, IPAddress, Country, ErrorCode
| take 20
```

```kusto
// Filter alerts to a specific detection service
AlertInfo
// | where Timestamp > ago(7d)
| where ServiceSource == "Microsoft Defender for Office 365"
// | project Timestamp, AlertId, Title, Category, Severity
| take 20
```

```kusto
// Filter Teams messages where delivery was not clean
MessageEvents
| where Timestamp > ago(7d)
| where DeliveryAction != "Delivered"
| project Timestamp, TeamsMessageId, SenderEmailAddress, DeliveryAction, ThreatTypes
| take 20
```

```kusto
// Filter Entra service principal sign-in failures
EntraSpnSignInEvents
| where Timestamp > ago(7d)
| where ErrorCode != 0
| project Timestamp, ServicePrincipalName, ApplicationId, IPAddress, ErrorCode
| take 20
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="equality-operators" name="equality-operators"></a>
## == / != (equality operators)

- `==` — exact match (case-sensitive)
- `!=` — not equal
- Used constantly inside `where` to filter by specific values.
- For **case-insensitive** equality use `=~` — covered in the [tilde](#tilde) section.

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
┌──────────────────────────────────────────┬─────────┐
│ Expression                               │ Result  │
├──────────────────────────────────────────┼─────────┤
│ "gmail.com" == "gmail.com"               │ true    │
│ "gmail.com" == "Gmail.com"               │ false   │
│ "gmail.com" != "yahoo.com"               │ true    │
│ "gmail.com" != "gmail.com"               │ false   │
└──────────────────────────────────────────┴─────────┘
</pre>

**Examples**

```kusto
// exact match — only rows where EmailDirection is exactly "Inbound"
EmailEvents
| where EmailDirection == "Inbound"
| take 10
```

```kusto
// not equal — exclude outbound mail
EmailEvents
| where EmailDirection != "Outbound"
| take 10
```

```kusto
// exact delivery location
EmailEvents
| where DeliveryLocation == "Inbox"
| take 10
```

```kusto
// case-sensitive
// Use =~ if you're unsure of casing
EmailEvents
| where EmailDirection == "inbound"  // returns 0 rows
| take 5
```

```kusto
// exclude a specific action type
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType != "FileAccessed"
| project Timestamp, AccountDisplayName, ActionType, Application
| take 10
```

```kusto
// ErrorCode 0 means success in Entra sign-ins
EntraSignInEvents
| where Timestamp > ago(1d)
| where ErrorCode == 0
| project Timestamp, AccountUpn, Application, Country
| take 10
```

```kusto
// non-zero ErrorCode means failure
EntraSignInEvents
| where Timestamp > ago(1d)
| where ErrorCode != 0
| project Timestamp, AccountUpn, Application, IPAddress, ErrorCode
| take 10
```

```kusto
// filter to a specific alert severity
AlertInfo
| where Timestamp > ago(7d)
| where Severity == "High"
| project Timestamp, Title, Severity, Category, ServiceSource
| take 10
```

```kusto
// exclude a severity level
AlertInfo
| where Timestamp > ago(7d)
| where Severity != "Informational"
| project Timestamp, Title, Severity, Category
| take 10
```

```kusto
// only rows for a specific entity kind
AlertEvidence
| where Timestamp > ago(7d)
| where EntityType == "User"
| project Timestamp, AlertId, AccountUpn, EvidenceRole
| take 10
```

```kusto
// only URLs embedded in the email body
EmailUrlInfo
| where Timestamp > ago(7d)
| where UrlLocation == "Body"
| project Timestamp, NetworkMessageId, Url, UrlDomain
| take 10
```

```kusto
// only blocked clicks
UrlClickEvents
| where Timestamp > ago(7d)
| where ActionType == "ClickBlocked"
| project Timestamp, AccountUpn, Url, IsClickedThrough
| take 10
```

```kusto
// exclude manual remediation
EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| where ActionType != "Manual Remediation"
| project Timestamp, NetworkMessageId, ActionType, DeliveryLocation
| take 10
```

```kusto
// only zip attachments
EmailAttachmentInfo
// | where Timestamp > ago(7d)
| where FileType == "zip"
| project Timestamp, SenderFromAddress, FileName, FileType
| take 10
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="and-or-in" name="and-or-in"></a>
## and / or / in

- Combine conditions.
- `in` is cleaner than multiple `or` statements.

**Examples**

```kusto
// Using 'in' for multiple values
IdentityLogonEvents
| where Timestamp > ago(7d)
| where Application in ("Microsoft 365", "Microsoft SharePoint Online")
| distinct Application, AccountUpn
| sample 3
```

```kusto
// Combining conditions
CloudAppEvents
| where Timestamp > ago(30d)
| where Application == "Microsoft Exchange Online" and ActionType has "MoveToDeletedItems"
| take 10
```

```kusto
CloudAppEvents
| where Timestamp > ago(30d)
| where Application == "Microsoft Exchange Online"
| where ActionType has "MoveToDeletedItems"
| take 10
```

```kusto
CloudAppEvents
| where Timestamp > ago(30d) 
    or Application == "Microsoft Exchange Online" 
    or ActionType has "MoveToDeletedItems"
| take 10
```

```kusto
// NOT in - exclude values
EmailEvents
| where SenderFromDomain !in ("contoso.com", "microsoft.com")
| take 10
```

```kusto
EmailEvents 
| where Timestamp between (datetime(2026-01-02T19:05:00Z) .. datetime(2026-01-02T19:10:00Z))
    and EmailDirection != 'Outbound'
    and (RecipientDomain == 'contoso.com' or RecipientDomain == 'contoso.onmicrosoft.com')
| project Timestamp, InternetMessageId, NetworkMessageId, RecipientEmailAddress, SenderFromAddress, Subject
```

```kusto
// Using 'in' for multiple alert severity levels
AlertInfo
| where Timestamp > ago(7d)
| where Severity in ("High", "Medium")
| project Timestamp, Title, Severity, Category, ServiceSource
| take 20
```

```kusto
// Combining and — sign-in failures from outside the US
EntraSignInEvents
| where Timestamp > ago(7d)
| where ErrorCode != 0
    and Country != "US"
| project Timestamp, AccountUpn, IPAddress, Country, ErrorCode
| take 20
```

```kusto
// Using 'in' for multiple alert evidence entity types
AlertEvidence
| where Timestamp > ago(7d)
| where EntityType in ("User", "Ip", "Url")
| project Timestamp, AlertId, EntityType, AccountUpn, RemoteIP
| take 20
```

```kusto
// NOT in — exclude low-risk Entra error codes
// 50125 = password reset, 50140 = keep me signed in
EntraSignInEvents
| where Timestamp > ago(7d)
| where ErrorCode !in (0, 50125, 50140)
| project Timestamp, AccountUpn, Application, IPAddress, ErrorCode
| take 20
```

```kusto
// or — Teams messages with threats OR non-delivered
MessageEvents
| where Timestamp > ago(7d)
| where ThreatTypes != ""
    or DeliveryAction != "Delivered"
| project Timestamp, TeamsMessageId, SenderEmailAddress, DeliveryAction, ThreatTypes
| take 20
```

```kusto
// and — URLs in body AND from external senders
EmailUrlInfo
| where Timestamp > ago(7d)
| where UrlLocation == "Body"
    and UrlDomain !endswith "microsoft.com"
| project Timestamp, NetworkMessageId, Url, UrlDomain
| take 10
```

```kusto
// in — multiple click action types
UrlClickEvents
| where Timestamp > ago(7d)
| where ActionType in ("ClickBlocked", "ClickAllowed")
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough
| take 10
```

```kusto
// in — multiple ZAP action types
EmailPostDeliveryEvents
// | where Timestamp > ago(7d)
| where ActionType in ("Phish ZAP", "Spam ZAP")
| project Timestamp, NetworkMessageId, ActionType, DeliveryLocation
| take 10
```

```kusto
// and — risky attachment: executable AND inbound
EmailAttachmentInfo
| where Timestamp > ago(7d)
| where FileExtension in (".exe", ".ps1", ".vbs")
    and SenderFromAddress !endswith "contoso.com"
| project Timestamp, SenderFromAddress, FileName, FileExtension
| take 10
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="tilde" name="tilde"></a>
## tilde ( ~ )

- Case-insensitive equality comparison.

**Examples**

```kusto
// Case-insensitive equality
EmailEvents
| where SenderFromAddress =~ "USER@CONTOSO.COM"
| take 5
```

```kusto
// in~ for case-insensitive list matching
CloudAppEvents
| where Application in~ ("MICROSOFT SHAREPOINT ONLINE", "microsoft onedrive for business", "microsoft Teams", "Microsoft EXCHANGE Online")
| take 10
```

```kusto
// Case-insensitive alert title match
AlertInfo
| where Timestamp > ago(7d)
| where Title =~ "suspicious sign-in activity"
| project Timestamp, Title, Severity, ServiceSource
| take 10
```

```kusto
// in~ — case-insensitive severity filter
AlertInfo
| where Timestamp > ago(7d)
| where Severity in~ ("HIGH", "high", "High")
| project Timestamp, Title, Severity, Category
| take 10
```

```kusto
// Case-insensitive user lookup in IdentityInfo
IdentityInfo
| where AccountUpn =~ "ADMIN@CONTOSO.COM"
| project AccountUpn, AccountDisplayName, Department, JobTitle, IsAccountEnabled
```

```kusto
// in~ — match Entra sign-in app names regardless of casing
EntraSignInEvents
| where Timestamp > ago(1d)
| where Application in~ ("MICROSOFT TEAMS", "microsoft teams", "Microsoft Teams")
| project Timestamp, AccountUpn, Application, IPAddress, Country
| take 10
```

```kusto
// =~ on UrlDomain — case-insensitive domain match
EmailUrlInfo
| where Timestamp > ago(7d)
| where UrlDomain =~ "Contoso.COM"
| project Timestamp, NetworkMessageId, Url, UrlDomain
| take 10
```

```kusto
// in~ — case-insensitive action type list match
UrlClickEvents
| where Timestamp > ago(7d)
| where ActionType in~ ("clickblocked", "CLICKBLOCKED")
| project Timestamp, AccountUpn, Url, ActionType
| take 10
```

```kusto
// =~ on ActionType — case-insensitive post-delivery match
EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| where ActionType =~ "phish zap"
| project Timestamp, NetworkMessageId, ActionType, DeliveryLocation
| take 10
```

```kusto
// =~ on FileType — case-insensitive match
EmailAttachmentInfo
| where Timestamp > ago(7d)
| where FileType =~ "PDF"
| project Timestamp, SenderFromAddress, FileName, FileType
| take 10
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="project" name="project"></a>
## project

- Selects which columns to include in output.
- Also used to rename columns.


**How `project` works**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
Before: All columns
┌───────────┬─────────────┬───────────┬──────────┬─────────┐
│ Timestamp │ Subject     │ Sender    │ Size     │ ...20+  │
├───────────┼─────────────┼───────────┼──────────┼─────────┤
│ 10:01     │ Invoice     │ a@ext.com │ 45000    │ ...     │
│ 10:02     │ Meeting     │ b@int.com │ 12000    │ ...     │
└───────────┴─────────────┴───────────┴──────────┴─────────┘
                         │
    | project Subject, Sender, Timestamp
                         │
                         ▼
After: Only selected columns
┌─────────────┬───────────┬───────────┐
│ Subject     │ Sender    │ Timestamp │
├─────────────┼───────────┼───────────┤
│ Invoice     │ a@ext.com │ 10:01     │
│ Meeting     │ b@int.com │ 10:02     │
└─────────────┴───────────┴───────────┘
</pre>

**Examples**

```kusto
EmailEvents
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject
| take 5
```

```kusto
// Rename columns for readability
IdentityLogonEvents
| project 
    SignInTime = Timestamp, 
    User = AccountUpn, 
    App = Application, 
    Country = Location
| take 5
```

```kusto
// Select key alert columns
AlertInfo
| where Timestamp > ago(7d)
| project Timestamp, Title, Severity, Category, ServiceSource
| take 10
```

```kusto
// Rename sign-in columns for readable output
EntraSignInEvents
| where Timestamp > ago(1d)
| project
    SignInTime   = Timestamp,
    User         = AccountUpn,
    App          = Application,
    Location     = Country,
    FailureCode  = ErrorCode
| take 10
```

```kusto
// Select key identity info columns
IdentityInfo
| project AccountUpn, AccountDisplayName, Department, JobTitle, City, Country, IsAccountEnabled
| take 10
```

```kusto
// Rename Teams message columns for clean output
MessageEvents
| where Timestamp > ago(7d)
| project
    EventTime  = Timestamp,
    MessageId  = TeamsMessageId,
    Sender     = SenderEmailAddress,
    Verdict    = DeliveryAction,
    Threat     = ThreatTypes
| take 10
```

```kusto
// Select alert evidence columns
AlertEvidence
| where Timestamp > ago(7d)
| project Timestamp, AlertId, EntityType, AccountUpn, RemoteIP, FileName, EvidenceRole
| take 10
```

```kusto
// Select key URL columns
EmailUrlInfo
| where Timestamp > ago(7d)
| project Timestamp, NetworkMessageId, Url, UrlDomain, UrlLocation
| take 10
```

```kusto
// Rename click columns for readable output
UrlClickEvents
| where Timestamp > ago(7d)
| project
    ClickTime      = Timestamp,
    User           = AccountUpn,
    ClickedUrl     = Url,
    WasBlocked     = ActionType,
    ClickedThrough = IsClickedThrough
| take 10
```

```kusto
// Select key post-delivery columns
EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| project Timestamp, NetworkMessageId, ActionType, DeliveryLocation, ThreatTypes
| take 10
```

```kusto
// Select and rename attachment columns
EmailAttachmentInfo
| where Timestamp > ago(7d)
| project
    ReceivedTime = Timestamp,
    Sender       = SenderFromAddress,
    File         = FileName,
    Extension    = FileExtension,
    SizeMB       = round(FileSize / 1048576.0, 2)
| take 10
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="project-away-project-reorder" name="project-away-and-project-reorder"></a>
## project-away / project-reorder

- `project-away`: Remove specific columns
- `project-reorder`: Change column order

**Examples**

```kusto
// Remove columns you don't need
CloudAppEvents
| project-away RawEventData, AdditionalFields
| take 5
```

```kusto
// review column order
IdentityLogonEvents
| getschema 
```

```kusto
// Reorder - put important columns first
IdentityLogonEvents
| project-reorder Timestamp, AccountUpn, Application, Location
| take 5
```

```kusto
// Remove verbose columns from AlertEvidence
AlertEvidence
| where Timestamp > ago(7d)
| project-away AdditionalFields
| take 5
```

```kusto
// review column order for EntraSignInEvents
EntraSignInEvents | getschema
```

```kusto
// Reorder Entra sign-in columns — most useful first
EntraSignInEvents
| where Timestamp > ago(1d)
| project-reorder Timestamp, AccountUpn, Application, IPAddress, Country, ErrorCode
| take 10
```

```kusto
// Reorder AlertInfo — key context up front
AlertInfo
| where Timestamp > ago(7d)
| project-reorder Timestamp, Title, Severity, Category, ServiceSource
| take 10
```

```kusto
// project-away verbose URL columns
EmailUrlInfo
| where Timestamp > ago(7d)
| project-away ReportId
| take 10
```

```kusto
// project-reorder — put user and URL first for readability
UrlClickEvents
| where Timestamp > ago(7d)
| project-reorder AccountUpn, Url, ActionType, Timestamp
| take 10
```

```kusto
// project-reorder post-delivery events — action first
EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| project-reorder ActionType, ThreatTypes, Timestamp, NetworkMessageId
| take 10
```

```kusto
// project-away ReportId from attachments — not needed for hunting
EmailAttachmentInfo
| where Timestamp > ago(7d)
| project-away ReportId, ThreatNames
| take 10
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="distinct" name="distinct"></a>
## distinct

- Returns unique values, removing duplicates.
- Great for finding "what exists" in your data.

**How `distinct` works**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
Before: Raw data with duplicates
┌─────────────────┐
│ SenderDomain    │
├─────────────────┤
│ gmail.com       │
│ outlook.com     │
│ gmail.com       │  <-- duplicate
│ yahoo.com       │
│ gmail.com       │  <-- duplicate
│ outlook.com     │  <-- duplicate
└─────────────────┘
         │
    | distinct SenderDomain
         │
         ▼
After: Unique values only
┌─────────────────┐
│ SenderDomain    │
├─────────────────┤
│ gmail.com       │
│ outlook.com     │
│ yahoo.com       │
└─────────────────┘
</pre>

**Examples**

```kusto
IdentityLogonEvents
| distinct Application
```

```kusto
CloudAppEvents
| distinct Application
```

```kusto
// Unique sender domains
EmailEvents
| distinct SenderFromDomain
```

```kusto
// Unique applications in sign-in logs
IdentityLogonEvents
| where Timestamp > ago(7d)
| distinct Application
```

```kusto
// Unique action types in CloudAppEvents
CloudAppEvents
| where Timestamp > ago(7d)
| distinct ActionType
```

```kusto
// Unique file types in attachments
EmailAttachmentInfo
| where Timestamp > ago(30d)
| distinct FileType
```

```kusto
// Unique URL domains in emails
EmailUrlInfo
| where Timestamp > ago(7d)
| distinct UrlDomain
| take 50
```

```kusto
// Unique applications where URLs were clicked
UrlClickEvents
| where Timestamp > ago(7d)
| distinct Workload
```

```kusto
// Unique post-delivery action types
EmailPostDeliveryEvents
// | where Timestamp > ago(30d)
| distinct ActionType
```

```kusto
// project vs distinct
EmailEvents
| where Timestamp >= ago(1d)
| project InternetMessageId
| take 5
```

```kusto
// project vs distinct
EmailEvents
| where Timestamp >= ago(1d)
| distinct InternetMessageId
| take 5
```

```kusto
// Unique alert severity levels
AlertInfo
| distinct Severity
```

```kusto
// Unique alert categories
AlertInfo
| where Timestamp > ago(30d)
| distinct Category
```

```kusto
// Unique countries in Entra sign-in events
EntraSignInEvents
| where Timestamp > ago(7d)
| distinct Country
```

```kusto
// Unique entity types in alert evidence
AlertEvidence
| where Timestamp > ago(7d)
| distinct EntityType, Application
```

```kusto
// Unique domains sent in Teams message URLs
MessageUrlInfo
| where Timestamp > ago(7d)
| distinct UrlDomain
| take 50
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="sort-by" name="sort-by"></a>
## sort by

- Orders rows by column(s).
- `asc` = ascending (A→Z, 1→9), `desc` = descending (Z→A, 9→1)

**How `sort by` works**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
Before: Unsorted
┌───────────┬─────────────┐
│ Timestamp │ Subject     │
├───────────┼─────────────┤
│ 10:30     │ Meeting     │
│ 09:15     │ Invoice     │
│ 14:45     │ Report      │
│ 11:00     │ Hello       │
└───────────┴─────────────┘
         │
    | sort by Timestamp desc
         │
         ▼
After: Newest first
┌───────────┬─────────────┐
│ Timestamp │ Subject     │
├───────────┼─────────────┤
│ 14:45     │ Report      │
│ 11:00     │ Hello       │
│ 10:30     │ Meeting     │
│ 09:15     │ Invoice     │
└───────────┴─────────────┘
</pre>

**Examples**

```kusto
// Most recent sign-ins first
IdentityLogonEvents
| sort by Timestamp desc
| take 10
```

```kusto
// Sort by multiple columns
CloudAppEvents
| where Timestamp > ago(1d)
| sort by AccountDisplayName asc // ignored
| sort by Timestamp desc
| take 20
```

```kusto
// Sort by multiple columns
// for each user, their newest event comes first, users grouped alphabetically
CloudAppEvents
| where Timestamp > ago(1d)
| sort by AccountDisplayName asc, Timestamp desc
| take 20
```

```kusto
// top 10 largest attachments
EmailAttachmentInfo
| where Timestamp >= ago(14d)
| extend
    FileSizeKB = round(FileSize / 1024.0, 2),
    FileSizeMB = round(FileSize / 1024.0 / 1024.0, 2)
| project FileName, FileSize, FileSizeKB, FileSizeMB
| sort by FileSize desc
| take 10

```

```kusto
// Most recent high-severity alerts first
AlertInfo
| where Timestamp > ago(7d)
| where Severity == "High"
| sort by Timestamp desc
| project Timestamp, Title, Severity, Category
| take 10
```

```kusto
// Sort Entra sign-in failures — newest first
EntraSignInEvents
| where Timestamp > ago(1d)
| where ErrorCode != 0
| sort by Timestamp desc
| project Timestamp, AccountUpn, IPAddress, Country, ErrorCode
| take 10
```

```kusto
// Sort Teams message threats — newest first
MessageEvents
| where Timestamp > ago(7d)
| where ThreatTypes != ""
| sort by Timestamp desc
| project Timestamp, TeamsMessageId, SenderEmailAddress, DeliveryAction, ThreatTypes
| take 10
```

```kusto
// Sort URLs by domain then newest first
EmailUrlInfo
| where Timestamp > ago(7d)
| sort by UrlDomain asc, Timestamp desc
| project Timestamp, UrlDomain, Url, UrlLocation
| take 20
```

```kusto
// Sort click events — most recent blocked clicks first
UrlClickEvents
| where Timestamp > ago(7d)
| where ActionType == "ClickBlocked"
| sort by Timestamp desc
| project Timestamp, AccountUpn, Url
| take 20
```

```kusto
// Sort post-delivery events — newest ZAP first
EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| sort by Timestamp desc
| project Timestamp, NetworkMessageId, ActionType, ThreatTypes
| take 20
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="contains-has-startswith-endswith" name="contains-has-startswith-endswith"></a>
## contains / has / startswith / endswith

- `has` - Token match (faster, uses index)
- `contains` - Substring match (slower)
- `startswith` / `endswith` - Prefix/suffix match

**Examples**

```kusto
CloudAppEvents
| where ActionType has "Create"
| take 5
```

```kusto
// has vs contains
EmailUrlInfo
// | where Url contains "www.facebook"
| where Url has "www.facebook"
```

```kusto
// contains - substring
EmailEvents
| where Subject contains "invoice"
| take 5
```

```kusto
// contains - substring
EmailEvents
| where Subject has "invoice"
| take 5
```

```kusto
// contains - substring
EmailEvents
| where Timestamp >= ago(14d)
| where EmailDirection == "Inbound"
// | where SenderFromDomain == "contoso.com"
// | where RecipientDomain == "fabrikam.com"
| where SenderDisplayName contains "Claire"
```

```kusto
EmailEvents
| where Timestamp >= ago(14d)
| where EmailDirection == "Inbound"
// | where SenderFromDomain == "contoso.com"
// | where RecipientDomain == "fabrikam.com"
| where SenderDisplayName has_any ("Claire","Rivera")
```

```kusto
// startswith
IdentityLogonEvents
| where Application startswith "Microsoft"
| distinct Application
```

```kusto
// has — fast token match on alert titles
AlertInfo
// | where Timestamp > ago(7d)
| where Title has "sign"
| project Timestamp, Title, Severity, ServiceSource
| take 10
```

```kusto
// has_any — alert categories related to credential attacks
AlertInfo
// | where Timestamp > ago(7d)
| where Category has_any ("CredentialAccess", "InitialAccess", "Impact")
| project Timestamp, Title, Category, Severity
| take 20
```

```kusto
// contains — partial match on sign-in user agent string
EntraSignInEvents
| where Timestamp > ago(1d)
| where UserAgent contains "python"
| project Timestamp, AccountUpn, Application, IPAddress, UserAgent
| take 10
```

```kusto
// startswith — find service principals by name prefix
EntraSpnSignInEvents
| where Timestamp > ago(7d)
| where ServicePrincipalName startswith "app-"
| project Timestamp, ServicePrincipalName, ApplicationId, IPAddress, ErrorCode
| take 10
```

```kusto
// has on UrlDomain — token match for a domain keyword
EmailUrlInfo
// | where Timestamp > ago(7d)
| where UrlDomain has "disney"
| project Timestamp, NetworkMessageId, Url, UrlDomain
| take 10
```

```kusto
// contains on Url — substring scan for a path pattern
UrlClickEvents
// | where Timestamp > ago(7d)
| where Url contains "/login"
| project Timestamp, AccountUpn, Url, ActionType
| take 10
```

```kusto
// has on ThreatTypes — token match
EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| project Timestamp, NetworkMessageId, ActionType, ThreatTypes
| take 10
```

```kusto
// has on FileName — find zip by extension token
EmailAttachmentInfo
// | where Timestamp > ago(7d)
| where FileName has ".zip"
| project Timestamp, SenderFromAddress, FileName, FileType
| take 10
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="negation" name="negation"></a>
## negation ( ! )

- Adds `!` to string operators to negate them: `!contains`, `!has`, `!in`, `!startswith`, `!endswith`
- For numeric or exact equality negation, use `!=` — covered in the [equality operators](#equality-operators) section.

**Common negation operators**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
┌───────────────┬───────────────┬────────────────────────────────────────────┐
| Operator      | Negates       | Example                                    |
├───────────────┼───────────────┼────────────────────────────────────────────┤
| !contains     | contains      | SenderDomain !contains "contoso"           |
| !has          | has           | Subject !has "invoice"                     |
| !in           | in            | Domain !in ("contoso.com", "google.com")   |
| !startswith   | startswith    | App !startswith "Microsoft"                |
| !endswith     | endswith      | FileName !endswith ".exe"                  |
└───────────────┴───────────────┴────────────────────────────────────────────┘
</pre>

**Examples**

```kusto
// Exclude internal domains
EmailEvents
| where SenderFromDomain !contains "contoso.com"
| take 10
```

```kusto
// not from these domains
EmailEvents
| where SenderFromDomain  !in (
    "contoso.com", 
    "starbucks.cafe",
    "abc.com"
    )
| take 10
```

```kusto
// exclude a delivery action substring
MessageEvents
| where Timestamp > ago(7d)
| where DeliveryAction !contains "Delivered"
| project Timestamp, TeamsMessageId, SenderEmailAddress, DeliveryAction, ThreatTypes
| take 10
```

```kusto
// exclude emails where subject contains the token "unsubscribe"
// Useful for filtering out marketing mail
EmailEvents
| where Timestamp > ago(7d)
| where Subject !has "unsubscribe"
| where EmailDirection == "Inbound"
| project Timestamp, SenderFromDomain, Subject
| take 10
```

```kusto
// exclude apps that start with "Microsoft"
EntraSignInEvents
| where Timestamp > ago(7d)
| where Application !startswith "Microsoft"
| distinct Application
| take 20
```

```kusto
// find attachments that are NOT PDFs
EmailAttachmentInfo
| where Timestamp > ago(7d)
| where FileName !endswith ".pdf"
| project Timestamp, SenderFromAddress, FileName, FileType
| take 10
```

```kusto
// exclude a list of known-safe alert categories
AlertInfo
| where Timestamp > ago(7d)
| where Category !in ("Impact", "ThreatManagement")
| project Timestamp, Title, Severity, Category
| take 10
```

```kusto
// exclude known safe domains from URL results
EmailUrlInfo
| where Timestamp > ago(7d)
| where UrlDomain !has "microsoft"
    and UrlDomain !has "contoso"
| project Timestamp, NetworkMessageId, Url, UrlDomain
| take 10
```

```kusto
// exclude known-safe click actions
UrlClickEvents
| where Timestamp > ago(7d)
| where ActionType !in ("ClickAllowed")
| project Timestamp, AccountUpn, Url, ActionType
| take 10
```

```kusto
// exclude automated remediation entries
EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| where ActionType !contains "Auto"
| project Timestamp, NetworkMessageId, ActionType, ThreatTypes
| take 10
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="count" name="count"></a>
## count

- `| count` - Standalone operator that returns total row count.
- Quick way to see how many rows match your filters.

**Examples**

```kusto
// Simple count - total rows
EmailEvents
| where Timestamp > ago(30d)
| count
```

```kusto
// Count unique users
CloudAppEvents
| where Timestamp > ago(7d)
| distinct AccountDisplayName
| count
```

```kusto
// Count high-severity alerts in last 7 days
AlertInfo
| where Timestamp > ago(7d)
| where Severity == "High"
| count
```

```kusto
// Count failed Entra sign-ins in last 24h
EntraSignInEvents
| where Timestamp > ago(1d)
| where ErrorCode != 0
| count
```

```kusto
// Count Teams messages with threat detections this week
MessageEvents
| where Timestamp > ago(7d)
| where ThreatTypes != ""
| count
```

```kusto
// Count URLs from external domains in last 7 days
EmailUrlInfo
| where Timestamp > ago(7d)
| where UrlDomain !endswith "contoso.com"
| count
```

```kusto
// Count blocked clicks in last 24h
UrlClickEvents
| where Timestamp > ago(1d)
| where ActionType == "ClickBlocked"
| count
```

```kusto
// Count ZAP actions this week
EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| where ActionType has "ZAP"
| count
```

```kusto
// Count attachments with risky extensions this month
EmailAttachmentInfo
| where Timestamp > ago(30d)
| where FileExtension in (".exe", ".ps1", ".vbs", ".bat", ".js")
| count
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="comparison-operators" name="comparison-operators"></a>
## >, <, >=, <= (numeric comparisons)

- For comparing **numeric** values: file sizes, counts, error codes, timestamps.
- Different from `==` / `!=` which test for exact equality — see the [equality operators](#equality-operators) section.

**Examples**

```kusto
// Files larger than 10MB
EmailAttachmentInfo
| where Timestamp >= ago(17d)
| where FileSize > 10000000
| take 10
```

```kusto
// Emails with multiple attachments
EmailEvents
| where AttachmentCount >= 3
| take 10
```

```kusto
// Sign-ins during off-hours (before 6am or after 8pm UTC)
EntraSignInEvents
| where Timestamp > ago(7d)
| where hourofday(Timestamp) < 6 or hourofday(Timestamp) >= 20
| project Timestamp, AccountUpn, Application, Country, ErrorCode
| take 20
```

```kusto
// Sign-in failures — non-zero error codes only
EntraSignInEvents
| where Timestamp > ago(1d)
| where ErrorCode > 0
| project Timestamp, AccountUpn, Application, IPAddress, ErrorCode
| take 10
```

```kusto
// Alert evidence: IP-based entities only (EntityType is a string,
// but RemotePort is numeric when populated)
AlertEvidence
| where Timestamp > ago(7d)
| where EntityType == "Ip"
| project Timestamp, AlertId, RemoteIP, EvidenceRole
| take 10
```

```kusto
// Alerts fired in the last hour only
AlertInfo
| where Timestamp >= ago(1h)
| project Timestamp, Title, Severity, Category
| take 10
```

```kusto
// URLs from large emails — message size > 5MB
// Join EmailUrlInfo with EmailEvents on NetworkMessageId
EmailUrlInfo
| where Timestamp > ago(7d)
| join kind=inner (
    EmailEvents
    | where EmailSize > 5242880
) on NetworkMessageId
| project Timestamp, SenderFromAddress, Url, EmailSize
| take 10
```

```kusto
// UrlClickEvents — clicks more than 3 seconds after email arrived
// IsClickedThrough == true means user bypassed the warning
UrlClickEvents
| where Timestamp > ago(7d)
| where IsClickedThrough == true
| project Timestamp, AccountUpn, Url, ActionType
| take 10
```

```kusto
// EmailPostDeliveryEvents — filter to recent ZAP actions
// Timestamp comparison — last 4 hours
EmailPostDeliveryEvents
| where Timestamp >= ago(4h)
| where ActionType has "ZAP"
| project Timestamp, NetworkMessageId, ActionType, ThreatTypes
| take 10
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="ago" name="time-and-ago"></a>
## ago()

- `ago()` - Relative time from now
- Time units: `d` (days), `h` (hours), `m` (minutes), `s` (seconds)

**Examples**

```kusto
// Last 7 days
EmailPostDeliveryEvents
| where Timestamp >= ago(7d)
| take 10
```

```kusto
// Last 2 hours
CloudAppEvents
| where Timestamp >= ago(2h)
| take 10
```

```kusto
// Last 24 hours of Entra sign-in failures
EntraSignInEvents
| where Timestamp >= ago(24h)
| where ErrorCode != 0
| take 10
```

```kusto
// Last 4 hours of high-severity alerts
AlertInfo
| where Timestamp >= ago(4h)
| where Severity == "High"
| project Timestamp, Title, Severity, ServiceSource
| take 10
```

```kusto
// Last 48 hours of Teams message threats
MessageEvents
| where Timestamp >= ago(48h)
| where ThreatTypes != ""
| project Timestamp, TeamsMessageId, SenderEmailAddress, ThreatTypes
| take 10
```

```kusto
// Last 48 hours of URL click events
UrlClickEvents
| where Timestamp >= ago(48h)
| project Timestamp, AccountUpn, Url, ActionType
| take 10
```

```kusto
// Last 14 days of email URL info
EmailUrlInfo
| where Timestamp >= ago(14d)
| distinct UrlDomain
| take 20
```

```kusto
// Last 72 hours of post-delivery events
EmailPostDeliveryEvents
| where Timestamp >= ago(72h)
| project Timestamp, NetworkMessageId, ActionType, ThreatTypes
| take 10
```

```kusto
// Last 30 days — distinct risky attachment senders
EmailAttachmentInfo
| where Timestamp >= ago(30d)
| where FileExtension in (".exe", ".ps1", ".vbs")
| distinct SenderFromAddress
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="between-datetime" name="between-datetime"></a>
## between / datetime

- Filter specific time ranges.

**Examples**

```kusto
// Specific date range
EmailEvents
| where Timestamp between (datetime(2026-01-01) .. datetime(2026-01-07))
| take 10
```

```kusto
// Between 3 days ago and 1 day ago
CloudAppEvents
| where Timestamp between (ago(3d) .. ago(1d))
| take 10
```

```kusto
// Specific date range for Entra sign-in events
EntraSignInEvents
| where Timestamp between (datetime(2026-01-01) .. datetime(2026-01-07))
| project Timestamp, AccountUpn, Application, IPAddress, ErrorCode
| take 10
```

```kusto
// Alert window: between 2 days ago and 6 hours ago
AlertInfo
| where Timestamp between (ago(2d) .. ago(6h))
| project Timestamp, Title, Severity, ServiceSource
| take 10
```

```kusto
// Teams message threats in a specific window
MessageEvents
| where Timestamp between (ago(3d) .. ago(1d))
| where ThreatTypes != ""
| project Timestamp, TeamsMessageId, SenderEmailAddress, ThreatTypes
| take 10
```

```kusto
// URL clicks in a specific investigation window
UrlClickEvents
| where Timestamp between (datetime(2026-01-10T08:00:00Z) .. datetime(2026-01-10T18:00:00Z))
| project Timestamp, AccountUpn, Url, ActionType
```

```kusto
// Post-delivery events in a specific incident window
EmailPostDeliveryEvents
| where Timestamp between (ago(3d) .. ago(1d))
| where ActionType has "ZAP"
| project Timestamp, NetworkMessageId, ActionType, ThreatTypes
```

```kusto
// EmailUrlInfo — URLs seen in a specific date range
EmailUrlInfo
| where Timestamp between (datetime(2026-01-01) .. datetime(2026-01-31))
| distinct UrlDomain
| take 20
```

```kusto
// EmailAttachmentInfo — risky files in a specific window
EmailAttachmentInfo
| where Timestamp between (ago(7d) .. ago(1d))
| where FileExtension in (".exe", ".ps1", ".vbs")
| project Timestamp, SenderFromAddress, FileName, FileExtension
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="time-formats" name="time-formats"></a>
## Time Formats

- KQL supports ISO8601 datetime.

**Examples**

```kusto
print dt = datetime(2026-01-07T13:00:00Z)
```

```kusto
print pastWeek = ago(7d), pastHour = ago(1h), past30Min = ago(30m)
```

```kusto
// ISO 8601 with timezone — common in audit and alert timestamps
print AlertTime = datetime(2026-01-15T09:30:00Z), WindowStart = datetime(2026-01-15T09:00:00Z)
```

```kusto
// Relative windows — common hunting patterns
print Last15m = ago(15m), LastHour = ago(1h), Last4h = ago(4h), Last24h = ago(24h), Last7d = ago(7d)
```

```kusto
// Datetime arithmetic — compute a window from a known event time
print
    IncidentStart  = datetime(2026-01-15T09:00:00Z),
    TwoHoursLater  = datetime(2026-01-15T09:00:00Z) + 2h,
    OneDayBefore   = datetime(2026-01-15T09:00:00Z) - 1d
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="now" name="now-and-utc"></a>
## now()

- `now()` returns current UTC time.
- All Advanced Hunting timestamps are UTC.
- Threat Explorer (UI) does detect timezone and display it in local timezone

**Examples**

```kusto
print CurrentTime = now()
```

```kusto
// How long ago was each sign-in?
IdentityLogonEvents
| where Timestamp > ago(1d)
| extend HoursAgo = datetime_diff('hour', now(), Timestamp)
| project Timestamp, HoursAgo, AccountUpn, Application
| take 5
```

```kusto
// How long ago was each alert fired?
AlertInfo
| where Timestamp > ago(1d)
| extend HoursAgo = datetime_diff('hour', now(), Timestamp)
| project Timestamp, HoursAgo, Title, Severity
| take 10
```

```kusto
// How many minutes ago did each sign-in failure occur?
EntraSignInEvents
| where Timestamp > ago(2h)
| where ErrorCode != 0
| extend MinutesAgo = datetime_diff('minute', now(), Timestamp)
| project Timestamp, MinutesAgo, AccountUpn, IPAddress, ErrorCode
| take 10
```

```kusto
// How many hours ago was each blocked click?
UrlClickEvents
| where Timestamp > ago(7d)
| where ActionType == "ClickBlocked"
| extend HoursAgo = datetime_diff("hour", now(), Timestamp)
| project HoursAgo, AccountUpn, Url, ActionType
| sort by HoursAgo asc
| take 10
```

```kusto
// How many hours since each ZAP action?
EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| where ActionType has "ZAP"
| extend HoursAgo = datetime_diff("hour", now(), Timestamp)
| project HoursAgo, NetworkMessageId, ActionType, ThreatTypes
| sort by HoursAgo asc
| take 10
```

```kusto
// How many days since each risky attachment was seen?
EmailAttachmentInfo
| where Timestamp > ago(30d)
| where FileExtension in (".exe", ".ps1", ".vbs")
| extend DaysAgo = datetime_diff("day", now(), Timestamp)
| project DaysAgo, SenderFromAddress, FileName, FileExtension
| sort by DaysAgo asc
| take 10
```

```kusto
// How long ago were external URLs last seen?
EmailUrlInfo
| where Timestamp > ago(14d)
| where UrlDomain !endswith "microsoft.com"
| extend DaysAgo = datetime_diff("day", now(), Timestamp)
| project DaysAgo, UrlDomain, Url
| sort by DaysAgo asc
| take 10
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="top" name="top"></a>
## top

- Returns the top N rows sorted by a column.
- Combines `sort by` and `take` in one operator.

**How `top` works**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
Before: Unsorted data
┌─────────────────┬───────────┐
│ SenderDomain    │ Count     │
├─────────────────┼───────────┤
│ gmail.com       │ 150       │
│ outlook.com     │ 890       │
│ yahoo.com       │ 45        │
│ hotmail.com     │ 320       │
│ aol.com         │ 12        │
└─────────────────┴───────────┘
              │
    | top 3 by Count desc
              │
              ▼
After: Top 3 by Count
┌─────────────────┬───────────┐
│ SenderDomain    │ Count     │
├─────────────────┼───────────┤
│ outlook.com     │ 890       │
│ hotmail.com     │ 320       │
│ gmail.com       │ 150       │
└─────────────────┴───────────┘
</pre>

**Examples**

```kusto
EmailEvents
| where Timestamp > ago(7d)
| summarize 
    EmailCount = count() 
    by SenderFromDomain
| top 20 by EmailCount desc
```

```kusto
EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has_any ("Phish", "Malware")
| summarize
    ThreatEmailCount = count(), 
    DistinctRecipients = dcount(RecipientEmailAddress)
    by SenderFromDomain
| top 10 by ThreatEmailCount desc
```

```kusto
EmailAttachmentInfo
| where Timestamp > ago(7d)
| summarize
    AttachmentCount = count(), 
    DistinctMessages = dcount(NetworkMessageId)
    by FileType
| top 10 by AttachmentCount desc
```

```kusto
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType == "FileUploaded"
| summarize
    UploadCount = count(), 
    DistinctUsers = dcount(AccountObjectId)
    by Application
| top 10 by UploadCount desc
```

```kusto
// Top 10 most triggered alert titles this week
AlertInfo
| where Timestamp > ago(7d)
| summarize
    AlertCount = count()
    by Title
| top 10 by AlertCount desc
```

```kusto
// Top 10 apps with most Entra sign-in failures
EntraSignInEvents
| where Timestamp > ago(7d)
| where ErrorCode != 0
| summarize
    FailureCount   = count(),
    DistinctUsers  = dcount(AccountUpn)
    by Application
| top 10 by FailureCount desc
```

```kusto
// Top 10 Teams message senders with threat detections
MessageEvents
| where Timestamp > ago(7d)
| where ThreatTypes != ""
| summarize
    ThreatMessages = count(),
    DistinctThreats = dcount(ThreatTypes)
    by SenderEmailAddress
| top 10 by ThreatMessages desc
```

```kusto
// Top 10 most clicked URLs
UrlClickEvents
| where Timestamp > ago(7d)
| summarize ClickCount = count() by Url
| top 10 by ClickCount desc
```

```kusto
// Top 10 post-delivery action types this month
EmailPostDeliveryEvents
| where Timestamp > ago(30d)
| summarize Count = count() by ActionType
| top 10 by Count desc
```

```kusto
// Top 10 URL domains seen in email
EmailUrlInfo
| where Timestamp > ago(7d)
| summarize Count = count() by UrlDomain
| top 10 by Count desc
```

```kusto
// Top 10 senders with risky attachments
EmailAttachmentInfo
| where Timestamp > ago(30d)
| where FileExtension in (".exe", ".ps1", ".vbs", ".bat")
| summarize Count = count() by SenderFromAddress
| top 10 by Count desc
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="extend" name="extend"></a>
## extend

- Adds new calculated columns to your results.
- Original columns are preserved.

**How `extend` works**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
Before: Original columns
┌─────────────┬──────────┐
│ FileName    │ FileSize │  (bytes)
├─────────────┼──────────┤
│ dogs.pdf    │ 1048576  │
│ cats.jpg    │ 524288   │
└─────────────┴──────────┘
              │
    | extend FileSizeKB = FileSize / 1024
    | extend FileSizeMB = FileSize / 1024 / 1024
              │
              ▼
After: Original + new columns
┌─────────────┬──────────┬────────────┬────────────┐
│ FileName    │ FileSize │ FileSizeKB │ FileSizeMB │
├─────────────┼──────────┼────────────┼────────────┤
│ dogs.pdf    │ 1048576  │ 1024       │ 1          │
│ cats.jpg    │ 524288   │ 512        │ 0.5        │
└─────────────┴──────────┴────────────┴────────────┘
</pre>

**Examples**

```kusto
// Convert ; round by 2 decimal
EmailAttachmentInfo
| extend FileSizeKB = round(FileSize / 1024.0, 2)
| extend FileSizeMB = round(FileSize / 1024.0 / 1024.0, 2)
| project FileName, FileType, FileSize, FileSizeKB, FileSizeMB
| sample 20
```

```kusto
EmailAttachmentInfo
| extend FileNameLower = tolower(FileName)
| project FileName, FileNameLower
| take 5
```

```kusto
EmailUrlInfo
| extend DomainAndLocation = strcat(UrlDomain, " (", UrlLocation, ")")
| project DomainAndLocation
| sample 10
```

```kusto
// Add a readable severity tag to alert output
AlertInfo
| where Timestamp > ago(7d)
| extend SeverityTag = strcat("[", Severity, "] ", Title)
| project Timestamp, SeverityTag, Category, ServiceSource
| take 10
```

```kusto
// Add a risk label based on Entra sign-in error code
EntraSignInEvents
| where Timestamp > ago(7d)
| extend SignInResult = iff(ErrorCode == 0, "Success", strcat("Failure (", tostring(ErrorCode), ")"))
| project Timestamp, AccountUpn, Application, Country, SignInResult
| take 20
```

```kusto
// Combine Teams URL info into a display label
MessageUrlInfo
| where Timestamp > ago(7d)
| extend UrlLabel = strcat(UrlDomain, " | ", Url)
| project Timestamp, TeamsMessageId, UrlLabel
| take 10
```

```kusto
// Add a location label to each URL
EmailUrlInfo
| where Timestamp > ago(7d)
| extend UrlLabel = strcat(UrlDomain, " (", UrlLocation, ")")
| project Timestamp, NetworkMessageId, UrlLabel, Url
| take 10
```

```kusto
// Classify click risk level
UrlClickEvents
// | where Timestamp > ago(7d)
| extend RiskLevel = iff(ActionType == "ClickBlocked", "High", "Low")
| project Timestamp, AccountUpn, Url, RiskLevel
| take 10
```

```kusto
// Add a human-readable action label to post-delivery events
EmailPostDeliveryEvents
// | where Timestamp > ago(7d)
| where ActionType !in ("Dynamic Delivery", "Manual Remediation", "")
| extend ActionLabel = strcat(ActionType, " → ", ThreatTypes)
| project Timestamp, NetworkMessageId, ActionLabel
| sample 20
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="live-scenario-emailattachmentinfo" name="live-scenario-emailattachmentinfo"></a>
## Live Scenario: EmailAttachmentInfo

### Scenario
Your security team received intelligence that threat actors are using `.iso`, `.vhd`, and `.img` files to deliver malware.

### Your Mission
Find all emails from the last 7 days with these potentially dangerous attachment types.

### Skills Tested
- `where` with time filter
- `in` operator
- `project` for clean output

```kusto
// Try









```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="live-scenario-emailevents" name="live-scenario-emailevents"></a>
## Live Scenario: EmailEvents

### Scenario
Users are complaining about spam. Management wants a list of external domains sending email to the organization.

### Your Mission
Find all unique external sender domains from the last 7 days, excluding known trusted domains, sorted alphabetically.

### Skills Tested
- `where` with time and direction filter
- `distinct` for unique values
- negation with `!in` to exclude trusted domains
- `sort by`

```kusto
// Try









```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="live-scenario-cloudappevents" name="live-scenario-cloudappevents"></a>
## Live Scenario: CloudAppEvents

### Scenario
Your manager wants a quick overview of user activity in cloud applications.

### Your Mission
Find all unique applications and action types users are performing, filtered to the last 7 days.

### Skills Tested
- `CloudAppEvents` table
- `where` with time filter
- `distinct` for unique values
- `sort by`

```kusto
// Try









```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="live-scenario-urlclickevents" name="live-scenario-urlclickevents"></a>
## Live Scenario: UrlClickEvents

### Scenario
Safe Links has been blocking suspicious URLs, but you want to identify users who clicked through warnings despite the risk.

### Your Mission
1. Find all blocked clicks in the last 7 days
2. Identify users who clicked through warnings

### Skills Tested
- `UrlClickEvents` table
- Filtering by `ActionType` and `IsClickedThrough`
- `sort by` and `take`

```kusto
// Try









```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="live-scenario-emailpostdeliveryevents" name="live-scenario-emailpostdeliveryevents"></a>
## Live Scenario: EmailPostDeliveryEvents

### Scenario
Your SOC wants to understand how effective Zero-hour Auto Purge (ZAP) has been at catching threats that bypassed initial detection.

### Your Mission
1. Find all ZAP actions in the last 7 days
2. Identify which threat types triggered ZAP

### Skills Tested
- `EmailPostDeliveryEvents` table
- Filtering by `ActionType`
- `distinct` and filtering

```kusto
// Try









```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="common-gotchas-tips" name="common-gotchas-tips"></a>
## Common Gotchas & Tips

### 1. `has` vs `contains` — Performance Matters

- `has` uses the **term index** — fast whole-word/token match
- `contains` does a **full substring scan** — checks every character of every string
- Rule of thumb: use `has` unless you specifically need mid-word matching

The performance gap widens dramatically on large tables like `EmailEvents`.

```kusto
// FAST — has uses the term index (whole-word token match)
// "invoice" must appear as a standalone word/token in the subject
EmailEvents
| where Timestamp > ago(7d)
| where Subject has "invoice"
| take 5
```

```kusto
// SLOWER — contains does a full substring scan on every row
// Use this only when you need to match mid-word (e.g. "inv" inside "invoice")
EmailEvents
| where Timestamp > ago(7d)
| where Subject contains "invoice"
| take 5
```

<a id="2-case-sensitivity" name="2-case-sensitivity"></a>
### 2. Case Sensitivity

- `==` is **case-sensitive** — `"gmail.com"` ≠ `"Gmail.com"`
- `=~` is **case-insensitive** — use when you can't guarantee casing
- `has` is case-insensitive by default
- `has_cs` is the case-sensitive version of `has`

```kusto
// GOTCHA: == is case-sensitive — this will return no results
// "GMAIL.COM" does not equal "gmail.com"
EmailEvents
| where Timestamp > ago(1d)
| where SenderFromDomain == "GMAIL.COM"
| take 1
```

```kusto
// FIX: use =~ for case-insensitive comparison
EmailEvents
| where Timestamp > ago(1d)
| where SenderFromDomain =~ "GMAIL.COM"
| take 1
```

<a id="3-has-wont-match-partial-words" name="3-has-wont-match-partial-words"></a>
### 3. `has` won't match partial words

`has` matches on whole tokens. If the word you're looking for is a substring of a larger word, `has` will miss it. Use `contains` in that case (and accept the performance trade-off).

```kusto
// GOTCHA: has "phish" does NOT match "phishing"
// The token in the string is "phishing" — "phish" is not a standalone token
AlertInfo
| where Timestamp > ago(7d)
| where Title has "phish"       // misses "phishing", "phished"
| take 5
```

```kusto
// FIX: use contains when you need partial/substring matching
// Accepts the slower scan in exchange for broader matching
AlertInfo
| where Timestamp > ago(7d)
| where Title contains "phish"  // matches "phish", "phishing", "phished"
| take 5
```

<a id="4-data-retention" name="4-data-retention"></a>
### 4. Data Retention

Advanced Hunting retains data for **30 days** by default. Queries using `ago(31d)` or longer will return no results — not an error, just an empty result set. If you see an unexpectedly empty result, check your time window first.

[back to top](#kql-for-email-security-beginner-series)

---
