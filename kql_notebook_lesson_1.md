<a id="kql-for-email-security-beginner-series" name="kql-for-email-security-beginner-series"></a>
# Microsoft Defender Advanced Hunting with KQL: Foundational

Learn to hunt threats with foundational query concepts such as filtering, projecting, and sorting using Kusto Query Language (KQL)

**Where to run these queries:** [Microsoft Defender portal](https://security.microsoft.com) → Investigation & response → Hunting → Advanced hunting

### Toolkit
| Table | What it tells you |
|-------|------------------|
| `EmailEvents` | Every email that touched your org |
| `EmailAttachmentInfo` | Files attached to those emails |
| `EmailUrlInfo` | Links embedded in emails |
| `UrlClickEvents` | Who clicked what, and when |
| `EmailPostDeliveryEvents` | What happened after delivery (ZAP, moves, deletes) |
| `IdentityLogonEvents` | User sign-ins and authentication |
| `CloudAppEvents` | User actions in cloud apps (Exchange, SharePoint, etc.) |
| `AlertInfo` | Security alerts and their metadata |
| `AlertEvidence` | Entities associated with each alert |
| `MessageEvents` | Microsoft Teams messages |
| `MessagePostDeliveryEvents` | Post-delivery actions on Teams messages |
| `MessageUrlInfo` | URLs embedded in Teams messages |
| `EntraIdSignInEvents` | Entra ID user sign-ins |
| `EntraIdSpnSignInEvents` | Entra ID service principal sign-ins |

<a id="toc" name="toc"></a>
# Table of Contents

1. [Table relationships quick reference](#table-relationships-quick-reference)
2. [getschema](#getschema)
3. [print](#print)
4. [comments ( // )](#comments)
5. [pipe ( | )](#pipe)
6. [Spacing](#spacing)
7. [Order matters](#order-matters)
8. [search](#search)
9. [take / limit / sample](#take-limit-sample)
10. [where](#where)
11. [== / != (equality operators)](#equality-operators)
12. [and / or / in](#and-or-in)
13. [tilde ( ~ )](#tilde)
14. [project / project-away / project-reorder](#project)
15. [distinct](#distinct)
16. [sort by / top](#sort-by)
17. [contains / has / startswith / endswith](#contains-has-startswith-endswith)
18. [negation ( ! )](#negation)
19. [count](#count)
20. [>, <, >=, <= (numeric comparisons)](#comparison-operators)
21. [Working with time](#working-with-time)
22. [extend](#extend)
23. [Live scenario: EmailAttachmentInfo](#live-scenario-emailattachmentinfo)
24. [Live scenario: EmailEvents](#live-scenario-emailevents)
25. [Live scenario: CloudAppEvents](#live-scenario-cloudappevents)
26. [Live scenario: UrlClickEvents](#live-scenario-urlclickevents)
27. [Live scenario: EmailPostDeliveryEvents](#live-scenario-emailpostdeliveryevents)
28. [Common gotchas & tips](#common-gotchas-tips)
---

<a id="table-relationships-quick-reference" name="table-relationships-quick-reference"></a>
## Table relationships quick reference

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

**Key join fields:**
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
CloudAppEvents
| where Timestamp > ago (1d)
| sample 5
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
EntraIdSignInEvents | getschema
```

```kusto
EntraIdSpnSignInEvents | getschema
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

**Examples**

```kusto
// Test time expressions
print CurrentTime = now(), OneWeekAgo = ago(7d), OneDayAgo = ago(1d)
```

```kusto
// Test time expressions - local time
print CurrentTime = now() -4h, OneWeekAgo = ago(7d) -4h, OneDayAgo = ago(1d) -4h
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
- Comment out any line to toggle it off without deleting it — useful when iterating on a long query. This works for entire pipe stages (`| where`, `| join`) as well as individual lines within a stage, such as specific columns in a multi-line `| project`.

**Examples**

```kusto
// Show last 10 email events
EmailEvents // this comment
| take 10
```

```kusto
// Look at recent sign-ins
IdentityLogonEvents
| where Timestamp > ago(1d)
| where Application == "Microsoft SharePoint Online"  // Uncomment to filter by app
| take 10
```

```kusto
// Browse recent identity logon events
IdentityLogonEvents
| where Timestamp > ago(1d)
// | where ActionType == "LogonFailed"  // Uncomment to filter failures only
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
// Toggling columns in a multi-line project
// Comment out any column to remove it from the output without breaking the query
EmailEvents
| where Timestamp > ago(1d)
| project
    Timestamp,
    SenderFromAddress,
    SenderFromDomain,
    RecipientEmailAddress,
    Subject,
    AttachmentCount,  // toggle off: uncomment to include
    ThreatTypes,      // toggle off: uncomment to include
    EmailDirection
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
EmailEvents // 652k results
// | where Timestamp > ago (7d)
// | where EmailDirection == "Inbound"
// | where SenderFromDomain has "gmail.com"
// | take 10
```

```kusto
EmailEvents
| where Timestamp > ago (7d)
// | where EmailDirection == "Inbound"
// | where SenderFromDomain has "gmail.com"
// | take 10
```

```kusto
EmailEvents
| where Timestamp > ago (7d)
| where EmailDirection == "Inbound"
// | where SenderFromDomain has "gmail.com"
// | take 10
```

```kusto
EmailEvents
| where Timestamp > ago (7d)
| where EmailDirection == "Inbound"
| where SenderFromDomain has "gmail.com"
// | take 10
```

```kusto
EmailEvents
| where Timestamp > ago (7d)
| where EmailDirection == "Inbound"
| where SenderFromDomain has "gmail.com"
| take 10
```

```kusto
IdentityLogonEvents
| where Timestamp > ago(1d)
| where Application has "Office"
| project Timestamp, AccountUpn, Application, Location
```

```kusto
CloudAppEvents
| where ActionType == "FileDownloaded"
| project Timestamp, AccountDisplayName, ActionType, Application
| take 5
```

```kusto
// Sign-in failures piped to clean output
IdentityLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonFailed"
| project Timestamp, AccountUpn, Application, IPAddress, Location, ActionType
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

[back to top](#kql-for-email-security-beginner-series)

---

<a id="spacing" name="spacing"></a>
## Spacing

- KQL ignores extra spaces and newlines.
- Indentation improves readability for complex queries.

**Examples**

```kusto
EmailEvents
| where SenderFromDomain has "gmail" and DeliveryLocation has "Inbox"
| project 
    // Subject, 
    RecipientEmailAddress, 
    NetworkMessageId
| take                                                                                                                                  5
```

```kusto
EmailEvents
| where
    SenderFromDomain has "gmail" 
    and DeliveryLocation has "Inbox"
| project Subject,
    RecipientEmailAddress, NetworkMessageId
| take 5
```

```kusto
// Spacing makes multi-condition filters readable
AlertInfo
| where
    // Timestamp > ago(7d)
    Severity == "High"
    and ServiceSource has "Defender"
| project 
    Timestamp,
    AlertId, 
    Title, 
    // Severity, 
    Category
| take                                                                                  10
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="order-matters" name="order-matters"></a>
## Order matters

KQL executes each pipe stage **left to right, top to bottom** — the output of one stage becomes the input of the next. That means the earlier you reduce the dataset, the less work every later stage has to do.

**Mental model:**
1. **Time filter first** — shrinks the dataset at the source using the built-in time index
2. **Column filters next** — narrow rows on indexed/selective columns
3. **Shape last** — `project`, `extend`, `distinct`, `sort` operate on what survived

Get wide data narrow *before* doing expensive operations on it.


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
// Now we narrow to just Medium severity rows — but only from the 7-day window we already scoped.
// The engine never touches older rows at all.
AlertInfo
// | where Timestamp > ago(7d)
| where Severity == "Medium"
```

```kusto
// Step 4 — Add a second column filter before any shaping
// Still filtering, not yet reshaping. More rows eliminated cheaply.
AlertInfo
// | where Timestamp > ago(7d)
| where Severity == "High"
| where ServiceSource == "AAD Identity Protection"
```

```kusto
// Step 5 — Shape the output with project
// project runs last, on only the rows that survived all filters.
// If project ran first, it would process every row in the table.
AlertInfo
// | where Timestamp > ago(7d)
| where Severity == "High"
| where ServiceSource == "AAD Identity Protection"
| project Timestamp, Title, Category, ServiceSource
```

```kusto
// Step 6 — Final query: sort and limit at the very end
// sort and take are the most expensive per-row operations.
// Running them on 20 rows is trivial. Running them on millions is not.
AlertInfo
// | where Timestamp > ago(21d)
// | where Severity == "High"
// | where ServiceSource contains "Sentinel"
| project Timestamp, Title, Category, ServiceSource
| sort by Timestamp desc
| take 20
```

**What happens if you get the order wrong?**

Filtering late is the most common mistake. KQL efficiency is about rows — the more rows that flow into each stage, the more work every stage has to do.

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
┌──────────────────────────────────────┬──────────────────────────────┐
│ Inefficient order:                   │ Efficient order:             │
├──────────────────────────────────────┼──────────────────────────────┤
│ AlertInfo                            │ AlertInfo                    │
│ | project Timestamp, Title, Severity │ | where Timestamp > ago(7d)  │
│ | where Timestamp > ago(7d)          │ | where Severity == "High"   │
│ | where Severity == "High"           │ | project Title, Severity    │
└──────────────────────────────────────┴──────────────────────────────┘
</pre>

In the inefficient version, the `where` clauses run against every row in the table — nothing has been filtered yet.  
In the efficient version, the time filter runs first and eliminates the vast majority of rows, so `project` and every other stage only touches what survived.

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
| where Timestamp > ago(1d)
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
| where Timestamp > ago(14d)
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
// why is this wrong?
EmailEvents
| where Timestamp > ago(1d)
| take 10
| sort by Timestamp desc
```

```kusto
// why is this right?
EmailEvents
| where Timestamp > ago(1d)
| sort by Timestamp desc
| take 10
```

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
// Efficient — time filter first on identity logons
IdentityLogonEvents
| where Timestamp > ago(1d)   // ← filter early
| where ActionType == "LogonFailed"
| project Timestamp, AccountUpn, Application, IPAddress, ActionType
```

```kusto
// Inefficient — project before filter wastes work
// all rows flow through project before the ActionType filter
IdentityLogonEvents
| project Timestamp, AccountUpn, Application, IPAddress, ActionType
| where Timestamp > ago(1d)
| where ActionType == "LogonFailed"
```

```kusto
// Efficient — filter alerts before extending labels
AlertInfo
// | where Timestamp > ago(7d)           // ← filter first
| where Severity == "High"            // ← second filter
| extend SevTag = strcat("[", Severity, "] ", Title)  // extend after
| project Timestamp, SevTag, Category, ServiceSource
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="search" name="search"></a>
## search

- Full-text search across all columns — all tables by default, or scoped with `in (Table1, Table2)`.
- Can also be written in piped form: `TableName | search "term"`
- Scope to a specific column with `ColumnName:"term"` — much cheaper than scanning all columns.
- Use for quick exploration, not production queries.
- `search` matches whole tokens and uses the term index — see [contains / has](#contains-has-startswith-endswith) for how this works under the hood.

**Examples**

```kusto
// Searches ALL tables — extremely broad and expensive
// Only use when you have no idea where the data lives
search "facebook"
```

```kusto
// Piped form — table first, then search
// Equivalent to: search in (EmailEvents) "phish"
EmailEvents // 53 columns
| where Timestamp > ago(7d)
| search "phish"
| take 10
```

```kusto
// Scoped to specific tables — cheaper than naked search
search in (EmailEvents, CloudAppEvents) "user@contoso.com"
| where Timestamp > ago(7d)
// | take 10
```

```kusto
// Column-scoped — targets one column instead of all columns
// Significantly cheaper when you know where the value lives
search in (EmailEvents) Subject:"invoice" and SenderFromAddress:"gmail.com"
| where Timestamp > ago(7d)
| take 10
```

```kusto
// * has — whole-token match across all string columns in the current row
EmailEvents
| where Timestamp > ago(7d)
| where * has "invoice"
| take 10
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="take-limit-sample" name="take-limit-sample"></a>
## take / limit / sample

- `take` / `limit` — Returns first N rows (same behavior)
- `sample` — Returns N random rows

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

<br>

> **Note:** `take` returns rows in no defined order — but typically surfaces rows from the most recently ingested segment. To return the earliest events instead, use `sort by Timestamp asc | take N`.

**Examples**

```kusto
EmailEvents
| take 10
```

```kusto
// Sample gives random rows - great for exploring data variety
CloudAppEvents | sample 20
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
IdentityLogonEvents
| where Timestamp > ago(1d)
| take 10
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
- Chaining multiple `where` clauses is equivalent to using `and` — each clause further narrows the result set. See [and / or / in](#and-or-in) for combining conditions within a single clause.

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
// | where Timestamp > ago(7d)
| where ActionType has "SoftDelete"
| take 10
```

```kusto
CloudAppEvents
| distinct Application
```

```kusto
// Find attachments with specific threat detections
EmailAttachmentInfo
| where Timestamp >= ago(1d)
| where isnotempty(ThreatTypes)
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
// | where Timestamp > ago(14d)
// | where ActionType == "ClickBlocked"
| project Timestamp, AccountUpn, Url, ActionType, ThreatTypes, Workload, IsClickedThrough
| take 25
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
// | where Timestamp > ago(7d)
// | where ActionType has "ZAP"
| project Timestamp, NetworkMessageId, RecipientEmailAddress, ActionType, ActionTrigger, ActionResult, DeliveryLocation
// | take 20
```

```kusto
EmailPostDeliveryEvents
| distinct ActionType
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
// Filter identity logon failures
IdentityLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonFailed"
| project Timestamp, AccountUpn, Application, IPAddress, Location, ActionType
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
// Filter identity logon failures by application
IdentityLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonFailed"
| project Timestamp, AccountUpn, Application, IPAddress, ActionType
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

| Expression | Result |
|---|---|
| "gmail.com" == "gmail.com" | true |
| "gmail.com" == "Gmail.com" | false |
| "gmail.com" != "yahoo.com" | true |
| "gmail.com" != "gmail.com" | false |

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
// filter to a specific action type
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft OneDrive for Business"
| where ActionType == "FileUploaded"
| project Timestamp, AccountDisplayName, ActionType, Application
| take 10
```

```kusto
CloudAppEvents
| distinct Application
```

```kusto
CloudAppEvents
| distinct Application, ActionType
```

```kusto
// LogonSuccess means success in identity logon events
IdentityLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonSuccess"
| project Timestamp, AccountUpn, Application, Location
| take 10
```

```kusto
// LogonFailed means failure in identity logon events
IdentityLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonFailed"
| project Timestamp, AccountUpn, Application, IPAddress, ActionType
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

- Combine conditions within a single `where` clause.
- `in` is cleaner than multiple `or` statements.
- `and` has higher precedence than `or` — use parentheses to make grouping explicit and avoid logic bugs: `where (A or B) and C`.
- For multi-condition filters, separate `where` clauses are often preferred over chaining `and` — one condition per line makes it easy to toggle individual filters on or off with a comment.

**Examples**

```kusto
// Using 'in' for multiple values
IdentityLogonEvents
| where Timestamp between (datetime(2026-05-29) .. datetime(2026-05-30))
| where Application in (
    "Microsoft 365", 
    "Microsoft SharePoint Online", 
    "Microsoft OneDrive for Business"
    )
| distinct Application, AccountUpn
// | sample 3
```

```kusto
// and — chaining conditions in a single where clause
CloudAppEvents
| where Timestamp > ago(30d)
| where Application == "Microsoft Exchange Online" and ActionType has "MoveToDeletedItems"
| take 10
```

```kusto
// Equivalent using multiple where clauses — easier to toggle individual conditions
CloudAppEvents
| where Timestamp > ago(30d) // and
| where Application == "Microsoft Exchange Online" // and
| where ActionType has "MoveToDeletedItems"
| take 10
```

```kusto
CloudAppEvents
| where Application == "Microsoft Teams"
| distinct ActionType
```

```kusto
// All three forms are equivalent — the engine treats them the same way
CloudAppEvents
| where Timestamp > ago(30d) and Application == "Microsoft Exchange Online" and ActionType has "MoveToDeletedItems"
| take 10
```

```kusto
// !in — case-sensitive exclusion; use !in~ for case-insensitive matching
EmailEvents
| where SenderFromDomain !in ("contoso.com", "microsoft.com")
| take 10
```

```kusto
EmailEvents 
| where Timestamp between (datetime(2026-01-02T19:05:00Z) .. datetime(2026-01-02T19:10:00Z))
    and EmailDirection != "Outbound"
    and (RecipientEmailAddress endswith "@contoso.com" or RecipientEmailAddress endswith "@contoso.onmicrosoft.com")
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
IdentityLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonFailed"
    and Location != "US"
| project Timestamp, AccountUpn, IPAddress, Location, ActionType
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
// NOT in — exclude specific logon action types
IdentityLogonEvents
| where Timestamp > ago(7d)
| where ActionType !in ("LogonSuccess", "LogonAttempted")
| project Timestamp, AccountUpn, Application, IPAddress, ActionType
| take 20
```

```kusto
// or — Teams messages with threats OR non-delivered
MessageEvents
// | where Timestamp > ago(7d)
| where ThreatTypes != ""
    or DeliveryAction != "Delivered"
// | project Timestamp, TeamsMessageId, SenderEmailAddress, DeliveryAction, ThreatTypes
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
EmailUrlInfo
| distinct UrlLocation
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
| where FileExtension in (
    ".exe", 
    // ".ps1", 
    ".vbs"
    )
    and SenderFromAddress !endswith "contoso.com"
| project Timestamp, SenderFromAddress, FileName, FileExtension
| take 10
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="tilde" name="tilde"></a>
## tilde ( ~ )

- Case-insensitive equality comparison.
- Most string operators are case-insensitive by default. Append `_cs` for the case-sensitive variant — `has_cs`, `contains_cs`, `startswith_cs`, `endswith_cs`.

**Examples**

```kusto
// Case-insensitive equality
EmailEvents
| where SenderFromAddress =~ "MIKE.TAYLOR@contoso.com"
| take 5
```

```kusto
EmailEvents
| where SenderFromDomain == ""
```

```kusto
// in~ for case-insensitive list matching
CloudAppEvents
| where Timestamp > ago (7d)
| where Application in~ ("MICROSOFT SHAREPOINT ONLINE", "microsoft onedrive for business", "microsoft Teams", "Microsoft EXCHANGE Online")
| sample 20
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
// in~ — match identity logon app names regardless of casing
IdentityLogonEvents
| where Timestamp > ago(1d)
| where Application in~ ("MICROSOFT TEAMS", "microsoft teams", "Microsoft Teams")
| project Timestamp, AccountUpn, Application, IPAddress, Location
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
## project / project-away / project-reorder

Three operators for shaping the column set of your output — `project` selects, `project-away` removes, `project-reorder` moves columns without dropping them.

### project

- Selects which columns to include in output.
- Also used to rename columns with `project` or `project-rename`

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
| sample 1
```

```kusto
EmailEvents
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject
| sample 5
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
// Rename columns for a cleaner report view — all other columns are preserved
IdentityLogonEvents
| project-rename
    SignInTime  = Timestamp,
    User        = AccountUpn,
    LoginResult = ActionType,
    App         = Application
| take 5
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
| sample 10
```

### project-away

- Removes specific columns — inverse of `project`; keeps everything except what you name.
- Useful when a table has many columns and you only want to drop a few.

**Examples**

```kusto
// full context, all columns
CloudAppEvents
| sample 5
```

```kusto
// Remove columns you don't need
CloudAppEvents
| project-away RawEventData, AdditionalFields
| take 5
```

### project-reorder

- Changes column order without dropping columns.
- Useful for putting the most relevant columns first in the output.

**Examples**

```kusto
// See current column order
IdentityLogonEvents
| getschema
```

```kusto
// Reorder — put most relevant columns first
IdentityLogonEvents
| project-reorder Timestamp, AccountUpn, Application, Location
| take 5
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
CloudAppEvents
| distinct Application
```

```kusto
// Unique sender domains
EmailEvents
| where Timestamp > ago(1h)
| distinct SenderMailFromAddress, SenderFromAddress
```

```kusto
// Unique application + action types pairs in CloudAppEvents
CloudAppEvents
| where Timestamp > ago(7d)
| distinct Application, ActionType
```

```kusto
// Unique file types in attachments
EmailAttachmentInfo
| where Timestamp > ago(30d)
| distinct FileExtension
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
| where Timestamp > ago(30d)
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
// Unique locations in identity logon events
IdentityLogonEvents
| where Timestamp > ago(7d)
| distinct Location
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
## sort by / top

Two ways to order and limit results — `sort by` gives full control over direction and column chaining; `top` combines sorting and row limiting into one operator.

### sort by

- Orders rows by column(s).
- `asc` = ascending (A→Z, 1→9), `desc` = descending (Z→A, 9→1)
- Omitting the direction defaults to `desc`.

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
| sort by Timestamp
| take 10
```

```kusto
// Sort by multiple columns — intentionally chained: each | sort by replaces the one before it
// Only the last | sort by applies. To sort by multiple columns use: | sort by col1 asc, col2 desc
CloudAppEvents
| where Timestamp > ago(1d)
| sort by AccountDisplayName asc
| sort by Timestamp desc
| take 20
```

```kusto
EmailEvents
| where Timestamp > ago (7d)
| distinct SenderFromAddress
| sort by SenderFromAddress asc
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
| where Timestamp >= ago(1d)
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
| project Timestamp, Title, Severity, Category
| sort by Timestamp desc
| take 10
```

```kusto
// Sort identity logon failures — newest first
IdentityLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonFailed"
| project Timestamp, AccountUpn, IPAddress, Location, ActionType
| sort by Timestamp desc
| take 10
```

```kusto
// Sort Teams message threats — newest first
MessageEvents
| where Timestamp > ago(7d)
| where ThreatTypes != ""
| project Timestamp, TeamsMessageId, SenderEmailAddress, DeliveryAction, ThreatTypes
| sort by Timestamp desc
| take 10
```

```kusto
// Sort URLs by domain then newest first
EmailUrlInfo
| where Timestamp > ago(7d)
| project Timestamp, UrlDomain, Url, UrlLocation
| sort by UrlDomain asc, Timestamp desc
| take 20
```

```kusto
// Sort click events — most recent blocked clicks first
UrlClickEvents
| where Timestamp > ago(7d)
| where ActionType == "ClickBlocked"
| project Timestamp, AccountUpn, Url
| sort by Timestamp desc
| take 20
```

```kusto
// Sort post-delivery events — newest ZAP first
EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| project Timestamp, NetworkMessageId, ActionType, ThreatTypes
| sort by Timestamp desc
| take 20
```

### top

- Returns the top N rows sorted by a column.
- Combines `sort by` and `take` in one operator.
- Omitting direction defaults to `desc` — largest values first.

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
// Most recent alerts — no summarize needed
AlertInfo
| where Timestamp > ago(7d)
| top 10 by Timestamp desc
```

```kusto
EmailEvents
| where Timestamp > ago(1d)
| summarize 
    EmailCount = count() 
    by SenderFromDomain
| top 20 by EmailCount desc
```

```kusto
EmailEvents
// | where Timestamp > ago(7d)
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
// Top 10 apps with most identity logon failures
IdentityLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonFailed"
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

<a id="contains-has-startswith-endswith" name="contains-has-startswith-endswith"></a>
## contains / has / startswith / endswith

- `has` — token match (faster, uses index)
- `contains` — matches part of a word (slower)
- `startswith` / `endswith` — prefix/suffix match on the full string value; faster than `contains` but slower than `has`

**Examples**

```kusto
CloudAppEvents
| where ActionType has "Create"
| sample 10
```

```kusto
CloudAppEvents
| where ActionType contains "Create"
| sample 10
```

### How `has` and `contains` work behind the scenes

KQL splits every string value into **tokens** at characters like spaces, `.`, `/`, `\`, `-`, `_`, and `@`. It stores these tokens in a term index so `has` can look up matches directly instead of reading every character.

**`has` — term index lookup**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
Value:  "www.facebook.com/login/page.html"
         |
         split into tokens
         |
         ▼
  ┌──────┬──────────┬─────┬───────┬──────┬───────┐
  │  [0] │    [1]   │ [2] │  [3]  │ [4]  │  [5]  │
  │  www │ facebook │ com │ login │ page │ html  │
  └──────┴──────────┴─────┴───────┴──────┴───────┘

  has "facebook"  →  look up "facebook" in index  →  found at [1]   (fast)
  has "face"      →  look up "face" in index      →  not found      ("face" is not a whole token)
</pre>

**`contains` — character-by-character scan**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
Value:  "www.facebook.com/login/page.html"
         |
         no index — reads every character looking for "face"
         |
  w  w  w  .  f  a  c  e  b  o  o  k  .  c  o  m  /  ...
             └──────────┘
              match found                              (reads every character, slow)
</pre>

<br>

> Use `has` by default — only switch to `contains` when you need to match part of a word (e.g., `face` inside `facebook`).

```kusto
// has vs contains
EmailUrlInfo
// | where Url contains "www.facebook"
| where Url has "www.facebook"
```

```kusto
// contains — substring
EmailEvents
| where Subject contains "invoice"
| take 5
```

```kusto
// has — token match
EmailEvents
| where Subject has "invoice"
| take 5
```

```kusto
// contains — substring
EmailEvents
| where Timestamp >= ago(14d)
| where EmailDirection == "Inbound"
// | where SenderFromDomain == "contoso.com"
// | where RecipientDomain == "fabrikam.com"
| where SenderDisplayName contains "Claire"
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
// contains — partial match on application name
IdentityLogonEvents
| where Timestamp > ago(1d)
| where Application contains "Office"
| project Timestamp, AccountUpn, Application, IPAddress, ActionType
| take 10
```

```kusto
// startswith — find sign-ins by application name prefix
IdentityLogonEvents
| where Timestamp > ago(7d)
| where Application startswith "Microsoft"
| project Timestamp, AccountUpn, Application, IPAddress, ActionType
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
// | where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| project Timestamp, NetworkMessageId, ActionType, ThreatTypes
| take 25
```

```kusto
EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, ThreatTypes, ThreatNames, DetectionMethods, ConfidenceLevel, DeliveryLocation
| take 25
```

```kusto
// has on FileName — find zip by extension token
EmailAttachmentInfo
// | where Timestamp > ago(7d)
| where FileName has ".zip"
| project Timestamp, SenderFromAddress, FileName, FileType
| take 10
```

### has variants

`hasprefix`, `hassuffix`, `has_any`, and `has_all` are token-aware extensions of `has`.

- `hasprefix` — any token in the string starts with the prefix
- `hassuffix` — any token in the string ends with the suffix
- `has_any(list)` — any token from the list is found in the string (token-based OR)
- `has_all(list)` — all tokens from the list are found in the string (token-based AND)

```kusto
// hasprefix — any token in the string starts with the prefix
// unlike startswith, matches even when the token isn't at the beginning of the string
// e.g. Subject "RE: Invoice pending" — hasprefix "inv" matches, startswith "inv" does not
EmailEvents
| where Timestamp > ago(7d)
| where Subject hasprefix "inv"
| project Timestamp, SenderFromAddress, Subject
| take 10
```

```kusto
// hassuffix — any token in the string ends with the suffix
// e.g. SenderFromDomain "hotmail.com" — token "hotmail" ends with "mail"
EmailEvents
| where Timestamp > ago(7d)
| where SenderFromDomain hassuffix "mail"
| distinct SenderFromDomain
| take 10
```

```kusto
EmailEvents
// | where Timestamp > ago(7d)
| where Subject has_any ("invoice", "payment")
```

```kusto
EmailUrlInfo
// | where UrlLocation == "Body"
| where Url contains "groupon.com"
```

```kusto
EmailEvents
| where Timestamp > ago(7d)
| where SenderFromAddress has_all ("microsoft","noreply")
```

```kusto
EmailUrlInfo
| where Timestamp > ago(7d)
| where UrlDomain has_any ("contoso", "fabrikam")
```

```kusto
// has_any — alerts related to credential or access attacks
AlertInfo
| where Timestamp > ago(7d)
| where Category has_any ("CredentialAccess", "InitialAccess", "Persistence")
| project Timestamp, Title, Category, Severity
| take 20
```

```kusto
// has_any — identity logons from automation or scripting apps
IdentityLogonEvents
| where Timestamp > ago(7d)
| where Application has_any ("PowerShell", "Graph Explorer", "Azure CLI")
| project Timestamp, AccountUpn, Application, IPAddress, ActionType
| take 20
```

```kusto
// has_any — Teams messages flagged with any threat type
MessageEvents
| where Timestamp > ago(7d)
| where ThreatTypes has_any ("Phish", "Malware", "Spam")
| project Timestamp, TeamsMessageId, SenderEmailAddress, DeliveryAction, ThreatTypes
| take 20
```

```kusto
// has_any — post-delivery events for ZAP or manual remediation
EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| where ActionType has_any ("ZAP", "Manual")
| project Timestamp, NetworkMessageId, ActionType, ThreatTypes
| take 20
```

```kusto
// has_any — match multiple name variants in the sender display name
EmailEvents
| where Timestamp >= ago(14d)
| where EmailDirection == "Inbound"
// | where SenderFromDomain == "contoso.com"
// | where RecipientDomain == "fabrikam.com"
| where SenderDisplayName has_any ("Claire","Rivera")
```

#### `has_any` vs `in` — key difference

`has_any` is **token-based**: it matches if the target string *contains* a term as a whole token.
`in` is **exact-match**: it only matches if the full field value equals one of the listed values.

| Expression | Matches `invoice_2024`? | Why |
|---|---|---|
| `Subject has_any ("invoice")` | Yes | `invoice` is a token in `invoice_2024` |
| `Subject in ("invoice")` | No | `invoice_2024` ≠ `invoice` (full value must match) |

```kusto
// Demonstrate has_any vs in divergence
// has_any matches on tokens — 'invoice' is a token inside 'invoice_2024'
// in requires the full field value to match exactly
print Subject = "invoice_2024"
| extend MatchesHasAny = Subject has_any ("invoice"),
         MatchesIn = Subject in ("invoice")
// Expected: MatchesHasAny = true, MatchesIn = false
```

### Wildcard column matching: `* has` and `* contains`

The `*` wildcard applies an operator across **every string column** in the current row — useful when you don't know which column holds the value.

| Expression | Mechanism | Cost |
|---|---|---|
| `where * has "term"` | Term index lookup across all columns | Low |
| `where * contains "term"` | Reads every character across all columns | High |

<br>

> Use `* has` when the target is a whole token. Use `* contains` only when you need to match part of a word and have already filtered the row count down.

```kusto
// * has — indexed token match across all columns
EmailEvents
| where Timestamp > ago(7d)
| where * has "phish"
| project Timestamp, SenderFromAddress, Subject, ThreatTypes
| take 10
```

```kusto
// * contains vs * has — same term, different cost
// Toggle between the two to see the difference in scope
EmailEvents
| where Timestamp > ago(7d)
// | where * has "invoice"      // whole token, uses index
| where * contains "invoice"    // substring, full scan
| take 10
```

**Operator reference**

| Operator | Mechanism | Cost | Use when |
|---|---|---|---|
| `has` | Term index lookup | Low | Matching a whole token |
| `hasprefix` | Term index prefix lookup | Low | Any token in the string starts with the prefix |
| `hassuffix` | Term index suffix lookup | Low | Any token in the string ends with the suffix |
| `has_any(list)` | Term index lookup (OR across list) | Low | Any listed token appears in the string |
| `has_all(list)` | Term index lookup (AND across list) | Low | All listed tokens appear in the string |
| `startswith` | String prefix scan | Medium | The full string starts with a value |
| `endswith` | String suffix scan | Medium | The full string ends with a value |
| `contains` | Reads every character | High | Matching part of a word |

<br>

> Use `has` for a single token. For multiple tokens, use `has_any` or `has_all` — the operator names signify clear intent.

[back to top](#kql-for-email-security-beginner-series)

---

<a id="negation" name="negation"></a>
## negation ( ! )

- Adds `!` to string operators to negate them: `!contains`, `!has`, `!in`, `!startswith`, `!endswith`
- For numeric or exact equality negation, use `!=` — covered in the [equality operators](#equality-operators) section.

**Common negation operators**

| Operator | Negates | Example |
|---|---|---|
| `!contains` | `contains` | `SenderDomain !contains "contoso"` |
| `!has` | `has` | `Subject !has "invoice"` |
| `!in` | `in` | `Domain !in ("contoso.com", "google.com")` |
| `!startswith` | `startswith` | `App !startswith "Microsoft"` |
| `!endswith` | `endswith` | `FileName !endswith ".exe"` |

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
| where SenderFromDomain !in (
    "contoso.com", 
    "starbucks.cafe",
    "abc.com"
    )
| take 10
```

```kusto
// exclude a delivery action substring
MessageEvents
// | where Timestamp > ago(7d)
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
IdentityLogonEvents
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
AlertInfo
| distinct Category
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

- `| count` — Standalone operator that returns total row count.
- Quick way to see how many rows match your filters.

**Examples**

```kusto
// Simple count - total rows
EmailEvents
// | where Timestamp > ago(30d)
| count
```

```kusto
// Count unique users
CloudAppEvents
| where Timestamp > ago(7d)
| distinct AccountId
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
// Count failed identity logon attempts in last 24h
IdentityLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonFailed"
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
// Emails with 3 or more URLs
EmailEvents
| where UrlCount >= 3
| take 10
```

```kusto
// Sign-ins during off-hours (before 6am or after 8pm UTC)
IdentityLogonEvents
| where Timestamp > ago(7d)
| where hourofday(Timestamp) < 6 or hourofday(Timestamp) >= 20
| project Timestamp, AccountUpn, Application, Location, ActionType
| take 20
```

```kusto
// Sign-in failures only
IdentityLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonFailed"
| project Timestamp, AccountUpn, Application, IPAddress, ActionType
| take 10
```

```kusto
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
// UrlClickEvents — users who clicked through a Safe Links warning
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

<a id="working-with-time" name="working-with-time"></a>
## Working with time

All Advanced Hunting timestamps are UTC. KQL provides several ways to express time windows — relative, fixed, and arithmetic.

### Time formats

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

### ago()

- `ago()` — Relative time from now
- Time units: `d` (days), `h` (hours), `m` (minutes), `s` (seconds)

**How `>` works with `ago()`**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
now       = 2026-05-18 10:00
ago(7d)   = 2026-05-11 10:00   (now minus 7 days)

past ◄─────────────────────────┬──────────────────────────► future
                               │
                   cutoff point 2026-05-11
                               │
               filtered ◄──────┴──────► kept
               (too old)               (last 7 days)
</pre>

Timestamps increase over time, so a larger value means a more recent event. `Timestamp > ago(7d)` reads as "more recent than the cutoff" — keeping everything in the last 7 days.

**Examples**

```kusto
EmailEvents
| where Timestamp > ago (2m)
```

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
// Last 24 hours of identity logon failures
IdentityLogonEvents
| where Timestamp >= ago(24h)
| where ActionType == "LogonFailed"
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

### between / datetime

- Filter specific time ranges.
- Syntax: `between (starttime .. endtime)` — both the start and end times are included.

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
// Specific date range for identity logon events
IdentityLogonEvents
| where Timestamp between (datetime(2026-01-01) .. datetime(2026-01-07))
| project Timestamp, AccountUpn, Application, IPAddress, ActionType
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
| where Timestamp between (ago(3h) .. ago(1h))
| where ThreatTypes != ""
| project Timestamp, TeamsMessageId, SenderEmailAddress, ThreatTypes
| take 10
```

```kusto
// URL clicks in a specific investigation window
UrlClickEvents
| where Timestamp between (datetime(2026-03-10T08:00:00Z) .. datetime(2026-03-10T18:00:00Z))
// | project Timestamp, AccountUpn, Url, ActionType
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

### now()

- `now()` returns current UTC time.
- All Advanced Hunting timestamps are UTC.
- Threat Explorer (UI) detects the timezone and displays it in local time.

**Examples**

```kusto
// print CurrentTime = now()
print CurrentTimeEastern = now() - 4h
```

### hourofday() / dayofweek() / monthofyear()

Extract a specific calendar component from a datetime value.
Useful for pattern detection — off-hours logins, weekend alerts, seasonal phishing campaigns.

| Function | Returns | Range |
|---|---|---|
| `hourofday(t)` | Hour as an integer | 0–23 |
| `dayofweek(t)` | Days since Sunday as a **timespan** | 0.00:00:00 (Sun) to 6.00:00:00 (Sat) |
| `monthofyear(t)` | Month as an integer | 1–12 |

Note: `dayofweek()` returns a **timespan**, not an integer. Use `toint(dayofweek(t) / 1d)` to get a 0–6 integer (0 = Sunday, 6 = Saturday).

**Examples**

```kusto
// hourofday() — email count by hour to detect off-hours activity
EmailEvents
| where Timestamp > ago(7d)
| extend Hour = hourofday(Timestamp)
| summarize EmailCount = count() by Hour
| sort by Hour asc
| render barchart
```

```kusto
// dayofweek() — flag weekend sign-in failures
// toint(dayofweek(t) / 1d) converts the returned timespan to 0-6 (0=Sun, 6=Sat)
IdentityLogonEvents
| where Timestamp > ago(30d)
| where ActionType == "LogonFailed"
| extend DayOfWeek = toint(dayofweek(Timestamp) / 1d)
| extend IsWeekend = DayOfWeek in (0, 6)
| summarize FailureCount = count() by DayOfWeek, IsWeekend
| sort by DayOfWeek asc
```

```kusto
// monthofyear() — compare alert volume across calendar months
AlertInfo
| where Timestamp > ago(365d)
| extend Month = monthofyear(Timestamp)
| summarize AlertCount = count() by Month
| sort by Month asc
| render barchart
```

### startofday() / startofweek() / startofmonth()

Round a timestamp down to the start of its calendar period.
Use these when you need to group by calendar boundaries rather than fixed-width buckets.

| Function | Rounds down to |
|---|---|
| `startofday(t)` | Start of the day (midnight UTC) |
| `startofweek(t)` | Start of the week (Sunday midnight UTC) |
| `startofmonth(t)` | First of the month (midnight UTC) |

**Examples**

```kusto
// startofday() — email volume by calendar day
// Compare with bin(Timestamp, 1d) — same result, more explicit intent
EmailEvents
| where Timestamp > ago(30d)
| summarize EmailCount = count() by Day = startofday(Timestamp)
| sort by Day asc
| render timechart
```

```kusto
// startofweek() — alert volume grouped by calendar week
AlertInfo
| where Timestamp > ago(90d)
| summarize AlertCount = count() by Week = startofweek(Timestamp)
| sort by Week asc
| render timechart
```

```kusto
// startofmonth() — email volume grouped by calendar month
EmailEvents
| where Timestamp > ago(90d)
| summarize EmailCount = count() by Month = startofmonth(Timestamp)
| sort by Month asc
| render timechart
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="extend" name="extend"></a>
## extend

- Adds new columns to your results.
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
// Convert file size; round to 2 decimal places
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
// Add a risk label based on logon outcome
IdentityLogonEvents
| where Timestamp > ago(7d)
| extend SignInResult = iif(ActionType == "LogonSuccess", "Success", "Failure")
| project Timestamp, AccountUpn, Application, Location, SignInResult
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
| extend RiskLevel = iif(ActionType == "ClickBlocked", "High", "Low")
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
## Live scenario: EmailAttachmentInfo

### Scenario
Your security team received intelligence that threat actors are using `.iso`, `.vhd`, and `.img` files to deliver malware.

### Your mission
Find all emails from the last 7 days with these potentially dangerous attachment types.

### Skills tested
- `where` with time filter
- `in` operator
- `project` for clean output

```kusto
// Try it yourself
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="live-scenario-emailevents" name="live-scenario-emailevents"></a>
## Live scenario: EmailEvents

### Scenario
Users are complaining about spam. Management wants a list of external domains sending email to the organization.

### Your mission
Find all unique external sender domains from the last 7 days, excluding known trusted domains, sorted alphabetically.

### Skills tested
- `where` with time and direction filter
- `distinct` for unique values
- negation with `!in` to exclude trusted domains
- `sort by`

```kusto
// Try it yourself
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="live-scenario-cloudappevents" name="live-scenario-cloudappevents"></a>
## Live scenario: CloudAppEvents

### Scenario
Your manager wants a quick overview of user activity in cloud applications.

### Your mission
Find all unique applications and action types users are performing, filtered to the last 7 days.

### Skills tested
- `CloudAppEvents` table
- `where` with time filter
- `distinct` for unique values
- `sort by`

```kusto
// Try it yourself
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="live-scenario-urlclickevents" name="live-scenario-urlclickevents"></a>
## Live scenario: UrlClickEvents

### Scenario
Safe Links has been blocking suspicious URLs, but you want to identify users who clicked through warnings despite the risk.

### Your mission
1. Find all blocked clicks in the last 7 days
2. Identify users who clicked through warnings

### Skills tested
- `UrlClickEvents` table
- Filtering by `ActionType` and `IsClickedThrough`
- `sort by` and `take`

```kusto
// Try it yourself
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="live-scenario-emailpostdeliveryevents" name="live-scenario-emailpostdeliveryevents"></a>
## Live scenario: EmailPostDeliveryEvents

### Scenario
Your SOC wants to understand how effective Zero-hour Auto Purge (ZAP) has been at catching threats that bypassed initial detection.

### Your mission
1. Find all ZAP actions in the last 7 days
2. Identify which threat types triggered ZAP

### Skills tested
- `EmailPostDeliveryEvents` table
- Filtering by `ActionType`
- `distinct` and filtering

```kusto
// Try it yourself
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="common-gotchas-tips" name="common-gotchas-tips"></a>
## Common gotchas & tips

### `has` vs `contains`: performance matters

- `has` uses the **term index** — fast token match
- `contains` **reads every character** — slower, no index
- Rule of thumb: use `has` unless you specifically need matching part of a word

The performance gap widens dramatically on large tables like `EmailEvents`.

```kusto
// FAST — has uses the term index (token match)
// "invoice" must appear as a standalone token in the subject
EmailEvents
| where Timestamp > ago(7d)
| where Subject has "invoice"
| take 5
```

```kusto
// SLOWER — contains reads every character on every row
// Use this only when you need to match part of a word (e.g. "inv" inside "invoice")
EmailEvents
| where Timestamp > ago(7d)
| where Subject contains "invoice"
| take 5
```

### Case sensitivity

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

### `has` won't match partial tokens

`has` matches on whole tokens. If the token you're looking for is part of a larger token, `has` will miss it. Use `contains` in that case (and accept the performance trade-off).

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

### Data retention

Advanced Hunting retains data for **30 days** by default. Extended retention up to 180 days is available with Microsoft Defender XDR add-on licensing. Queries beyond your retention window return no results — not an error, just an empty result set. If you see an unexpectedly empty result, check your time window first.

[back to top](#kql-for-email-security-beginner-series)

---
