<a id="kql-for-email-security-beginner-series" name="kql-for-email-security-beginner-series"></a>
# KQL for Email Security — Beginner Series

Learn to hunt threats in Microsoft 365 email using KQL.

**Where to run these queries:**  

[Microsoft Defender portal](https://security.microsoft.com) → Investigation & response → Hunting → Advanced hunting

<a id="toolkit" name="toolkit"></a>
### Toolkit
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

> Run all examples in **Microsoft Defender portal → Hunting → Advanced hunting**

<a id="toc" name="toc"></a>

<a id="table-of-contents" name="table-of-contents"></a>
# Table of Contents

1. [Table Relationships Quick Reference](#table-relationships-quick-reference)
2. [getschema](#getschema)
3. [print](#print)
4. [// comments](#comments)
5. [pipe ( | )](#pipe)
6. [spacing](#spacing)
7. [order matters](#order-matters)
8. [search](#search)
9. [take / limit / sample](#take-limit-sample)
10. [where](#where)
11. [and / or / in](#and-or-in)
12. [tilde ( ~ )](#tilde)
13. [project](#project)
14. [project-away / project-reorder](#project-away-project-reorder)
15. [distinct](#distinct)
16. [sort by](#sort-by)
17. [contains / has / startswith / endswith](#contains-has-startswith-endswith)
18. [negation ( ! )](#negation)
19. [count](#count)
20. [Comparison Operators](#comparison-operators)
21. [ago()](#ago)
22. [between / datetime](#between-datetime)
23. [Time Formats](#time-formats)
24. [now()](#now)
25. [top](#top)
26. [extend](#extend)
27. [Live Scenario: EmailAttachmentInfo](#live-scenario-emailattachmentinfo)
28. [Live Scenario: EmailEvents](#live-scenario-emailevents)
29. [Live Scenario: CloudAppEvents](#live-scenario-cloudappevents)
30. [Live Scenario: UrlClickEvents](#live-scenario-urlclickevents)
31. [Live Scenario: EmailPostDeliveryEvents](#live-scenario-emailpostdeliveryevents)
32. [Common Gotchas & Tips](#common-gotchas-tips)
---

<a id="table-relationships-quick-reference" name="table-relationships-quick-reference"></a>
## Table Relationships Quick Reference

Understanding how tables relate is critical for effective hunting:

<div style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25; white-space: pre;">
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
</div>




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

```kql
EmailEvents | getschema
```

```kql
IdentityLogonEvents | getschema
```

```kql
CloudAppEvents | getschema
```

```kql
EmailAttachmentInfo | getschema
```

```kql
EmailUrlInfo | getschema
```

```kql
UrlClickEvents | getschema
```

```kql
EmailPostDeliveryEvents | getschema
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="print---testing-expressions" name="print---testing-expressions"></a>
<a id="print" name="print-testing-expressions"></a>
## print

- Use `print` to test expressions without querying tables.
- Great for learning time functions, string manipulation, etc.
- 
**Examples**

```kql
// Test time expressions
print CurrentTime = now(), OneWeekAgo = ago(7d), OneDayAgo = ago(1d)
```

```kql
// Test string functions
print 
    Original = "user@CONTOSO.com",
    Lower = tolower("user@CONTOSO.com"),
    Upper = toupper("user@contoso.com")
```

```kql
// Test math expressions
print 
    BytesToKB = 1048576 / 1024,
    BytesToMB = 1048576 / 1024 / 1024
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="-comments" name="-comments"></a>
<a id="comments" name="comments"></a>
## // comments

- Use `//` to add inline comments to queries.
- Helps document your logic for future reference.

**Examples**

```kql
// Show last 10 email events
EmailEvents
| take 10
```

```kql
// Look at recent sign-ins
IdentityLogonEvents
| where Timestamp > ago(1d)
// | where Application == "Microsoft SharePoint Online"  // Uncomment to filter by app
| take 10
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="pipe" name="pipe"></a>
## pipe ( | )

- The pipe passes data from one operation to the next.
- Read queries top-to-bottom, left-to-right.

---

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

```kql
EmailEvents
| where SenderFromDomain == "gmail.com"
| project Subject, SenderFromAddress, RecipientEmailAddress
```

```kql
IdentityLogonEvents
| where Timestamp > ago(1d)
// | where Application has "Office"
| project Timestamp, AccountUpn, Application, Location
```

```kql
CloudAppEvents
| where ActionType == "FileDownloaded"
| take 5
| project Timestamp, AccountDisplayName, ActionType, Application
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="spacing" name="spacing"></a>
<a id="spacing" name="spacing"></a>
## spacing

- KQL ignores extra spaces and newlines.
- Indentation improves readability for complex queries.

**Examples**

```kql
EmailEvents
| where
    SenderFromDomain has "gmail"
    and DeliveryLocation has "Inbox"
| project Subject,
    RecipientEmailAddress, NetworkMessageId
| take                                                                                                                        5
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="order-matters" name="order-matters"></a>
<a id="order-matters" name="order-matters"></a>
## order matters

- KQL executes queries top to bottom.
- Placing filters early improves performance.

**Examples**

```kql
// Efficient — Filtering before projection
EmailEvents
| where SenderFromDomain == "gmail.com"
| project Timestamp, SenderFromAddress, Subject
```

```kql
// Inefficient — Projection before filtering
EmailEvents
// | where Timestamp >= ago(7d)
| project SenderFromDomain, Subject
| where SenderFromDomain == "gmail.com"
```

```kql
// Efficient — distinct then sort
EmailEvents
| distinct SenderFromDomain
| sort by SenderFromDomain desc
| take 10
```

```kql
// Less efficient — sort everything first
EmailEvents
| sort by SenderFromDomain
| distinct SenderFromDomain
| take 10
```

```kql
// Efficient - Filter before projection
IdentityLogonEvents
| where Timestamp > ago(1d)
| where Application == "Microsoft 365"
| project Timestamp, AccountUpn, Location, Application
```

```kql
// Inefficient — Expensive extend before filtering
// extend computes geo for every row
// many of the rows get discard by the where
IdentityLogonEvents
| extend Geo = strcat(Location, "-", AccountUpn)
| where Timestamp > ago(1d)
| where Application == "Microsoft 365"
| project Timestamp, AccountUpn, Location, Geo
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="search" name="search"></a>
## search

- Full-text search across all columns.
- Use for quick exploration, not production queries.

**Examples**

```kql
search "facebook"
```

```kql
// Search within specific tables
search in (IdentityLogonEvents, CloudAppEvents) "failed"
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="take-limit-sample" name="take-limit-sample"></a>
## take / limit / sample

- `take` / `limit` - Returns first N rows (same behavior)
- `sample` - Returns N random rows

---

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
  (deterministic)        (different each run)
</pre>

**Examples**

```kql
EmailEvents
| take 25
```

```kql
IdentityLogonEvents | limit 5
```

```kql
// Sample gives random rows - great for exploring data variety
CloudAppEvents | sample 1
```

```kql
EmailAttachmentInfo | take 10
```

```kql
EmailUrlInfo | take 10
```

```kql
UrlClickEvents | take 10
```

```kql
EmailPostDeliveryEvents 
| where Timestamp >= ago(24h)
// | take 10
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="where" name="where"></a>
## where

- Filters rows based on conditions.
- Only rows where the condition is `true` pass through.

---

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

```kql
EmailEvents
| where Timestamp >= ago(1d)
| where EmailDirection == "Inbound"
| where SenderFromDomain == "yahoo.com"
| take 10
```

```kql
// Filter sign-ins by result
IdentityLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonFailed"
| take 10
```

```kql
// Filter cloud events by action
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType has "SoftDelete"
| take 10
```

```kql
// Find attachments with specific threat detections
EmailAttachmentInfo
| where Timestamp > ago(1d)
// | where isnotempty(ThreatTypes)
| project Timestamp, SenderFromAddress, RecipientEmailAddress, FileName, FileType, ThreatTypes, ThreatNames
| take 20
```

```kql
// Find emails containing URLs from specific domains
EmailUrlInfo
| where Timestamp > ago(7d)
| where UrlDomain has "twitter" or UrlDomain has "facebook"
| project Timestamp, NetworkMessageId, Url, UrlDomain, UrlLocation
| take 20
```

```kql
EmailUrlInfo
// | where Timestamp > ago(1d)
| where UrlLocation == "Attachment"
// | where Url contains "facebook"
| project Timestamp, NetworkMessageId, Url, UrlDomain, UrlLocation
| take 20
```

```kql
EmailUrlInfo
| distinct UrlLocation
```

```kql
UrlClickEvents
| where Timestamp > ago(30d)
// | where ActionType == "ClickBlocked"
// | project Timestamp, AccountUpn, Url, ActionType, ThreatTypes, Workload
```

```kql
UrlClickEvents
| where Timestamp > ago(30d)
// | where IsClickedThrough == true
| project Timestamp, AccountUpn, Url, ThreatTypes, Workload
| take 20
```

```kql
EmailPostDeliveryEvents
// | where Timestamp > ago(30d)
| where ActionType has "ZAP"
| project Timestamp, NetworkMessageId, RecipientEmailAddress, ActionType, ActionTrigger, ActionResult, DeliveryLocation
| take 20
```

```kql
// Find manual remediation actions by admins
EmailPostDeliveryEvents
| where Timestamp > ago(30d)
| where ActionType == "Manual Remediation"
| project Timestamp, NetworkMessageId, RecipientEmailAddress, Action, ActionTrigger, ActionResult
| take 20
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="and-or-in" name="and-or-in"></a>
<a id="and-or-in" name="and-or-in"></a>
## and / or / in

- Combine conditions.
- `in` is cleaner than multiple `or` statements.

**Examples**

```kql
// Using 'in' for multiple values
IdentityLogonEvents
| where Timestamp > ago(7d)
| where Application in ("Microsoft 365", "Microsoft SharePoint Online")
| distinct Application, AccountUpn
| take 20
```

```kql
// Combining conditions
CloudAppEvents
| where Timestamp > ago(30d)
| where Application == "Microsoft Exchange Online" and ActionType has "MoveToDeletedItems"
| take 10
```

```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where Application == "Microsoft Exchange Online"
| where ActionType has "MoveToDeletedItems"
| take 10
```

```kql
CloudAppEvents
| where Timestamp > ago(30d) 
    or Application == "Microsoft Exchange Online" 
    or ActionType has "MoveToDeletedItems"
| take 10
```

```kql
// NOT in - exclude values
EmailEvents
| where SenderFromDomain !in ("contoso.com", "microsoft.com")
| take 10
```

```kql
EmailEvents 
| where Timestamp between (datetime(2026-01-02T19:05:00Z) .. datetime(2026-01-02T19:10:00Z))
    and EmailDirection != 'Outbound'
    and (RecipientDomain == 'contoso.com' or RecipientDomain == 'contoso.onmicrosoft.com')
| project Timestamp, InternetMessageId, NetworkMessageId, RecipientEmailAddress, SenderFromAddress, Subject
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="tilde--" name="tilde--"></a>
<a id="tilde" name="tilde"></a>
## tilde ( ~ )

- Case-insensitive equality comparison.

**Examples**

```kql
// Case-insensitive equality
EmailEvents
| where SenderFromAddress =~ "USER@CONTOSO.COM"
| take 5
```

```kql
// in~ for case-insensitive list matching
CloudAppEvents
| where Application in~ ("MICROSOFT SHAREPOINT ONLINE", "microsoft onedrive for business", "microsoft Teams", "Microsoft EXCHANGE Online")
| take 10
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="project" name="project"></a>
## project

- Selects which columns to include in output.
- Also used to rename columns.

---

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

```kql
EmailEvents
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject
| take 5
```

```kql
// Rename columns for readability
IdentityLogonEvents
| project 
    SignInTime = Timestamp, 
    User = AccountUpn, 
    App = Application, 
    Country = Location
| take 5
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="project-away-project-reorder" name="project-away-and-project-reorder"></a>
<a id="project-away-project-reorder" name="project-away-and-project-reorder"></a>
## project-away / project-reorder

- `project-away`: Remove specific columns
- `project-reorder`: Change column order

**Examples**

```kql
// Remove columns you don't need
CloudAppEvents
| project-away RawEventData, AdditionalFields
| take 5
```

```kql
IdentityLogonEvents
| getschema 
```

```kql
// Reorder - put important columns first
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

---

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

```kql
IdentityLogonEvents
| distinct Application
```

```kql
CloudAppEvents
| distinct Application
```

```kql
// Unique sender domains
EmailEvents
| distinct SenderFromDomain
```

```kql
EmailEvents
| where Timestamp >= ago(14d)
| where SenderFromDomain == "mail.salesforce.com"
```

```kql
// Unique applications in sign-in logs
IdentityLogonEvents
| where Timestamp > ago(7d)
| distinct Application
```

```kql
// Unique action types in CloudAppEvents
CloudAppEvents
| where Timestamp > ago(7d)
| distinct ActionType
```

```kql
// Unique file types in attachments
EmailAttachmentInfo
| where Timestamp > ago(30d)
| distinct FileType
```

```kql
// Unique URL domains in emails
EmailUrlInfo
| where Timestamp > ago(7d)
| distinct UrlDomain
| take 50
```

```kql
// Unique applications where URLs were clicked
UrlClickEvents
| where Timestamp > ago(7d)
| distinct Workload
```

```kql
// Unique post-delivery action types
EmailPostDeliveryEvents
// | where Timestamp > ago(30d)
| distinct ActionType
```

```kql
// project vs distinct
EmailEvents
| where Timestamp >= ago(1d)
| project InternetMessageId
| take 5
```

```kql
// project vs distinct
EmailEvents
| where Timestamp >= ago(1d)
| distinct InternetMessageId
| take 5
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="sort-by" name="sort-by"></a>
## sort by

- Orders rows by column(s).
- `asc` = ascending (A→Z, 1→9), `desc` = descending (Z→A, 9→1)

---

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

```kql
// Most recent sign-ins first
IdentityLogonEvents
| sort by Timestamp desc
| take 10
```

```kql
// Sort by multiple columns
CloudAppEvents
| where Timestamp > ago(1d)
| sort by AccountDisplayName asc // ignored
| sort by Timestamp desc
| take 20
```

```kql
// Sort by multiple columns
// for each user, their newest event comes first, users grouped alphabetically
CloudAppEvents
| where Timestamp > ago(1d)
| sort by AccountDisplayName asc, Timestamp desc
| take 20
```

```kql
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

[back to top](#kql-for-email-security-beginner-series)

---

<a id="contains-has-startswith-endswith" name="contains-has-startswith-endswith"></a>
<a id="contains-has-startswith-endswith" name="contains-has-startswith-endswith"></a>
## contains, has, startswith, endswith

- `has` - Token match (faster, uses index)
- `contains` - Substring match (slower)
- `startswith` / `endswith` - Prefix/suffix match

**Examples**

```kql
CloudAppEvents
| where ActionType has "Create"
| take 5
```

```kql
// has vs contains
EmailUrlInfo
// | where Url contains "www.facebook"
| where Url has "www.facebook"
```

```kql
// contains - substring
EmailEvents
| where Subject contains "invoice"
| take 5
```

```kql
// contains - substring
EmailEvents
| where Subject has "invoice"
| take 5
```

```kql
// contains - substring
EmailEvents
| where Timestamp >= ago(14d)
| where EmailDirection == "Inbound"
// | where SenderFromDomain == "contoso.com"
// | where RecipientDomain == "fabrikam.com"
| where SenderDisplayName contains "Claire"
```

```kql
EmailEvents
| where Timestamp >= ago(14d)
| where EmailDirection == "Inbound"
// | where SenderFromDomain == "contoso.com"
// | where RecipientDomain == "fabrikam.com"
| where SenderDisplayName has_any ("Claire","Rivera")
```

```kql
// startswith
IdentityLogonEvents
| where Application startswith "Microsoft"
| distinct Application
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="negation--" name="negation--"></a>
<a id="negation" name="negation"></a>
## negation ( ! )

- Negates conditions: `!=`, `!contains`, `!has`, `!in`

**Examples**

```kql
// Exclude internal domains
EmailEvents
| where SenderFromDomain !contains "contoso.com"
| take 10
```

```kql
// not from these domains
EmailEvents
| where SenderFromDomain  !in (
    "contoso.com", 
    "starbucks.cafe",
    "abc.com"
    )
| take 10
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="count" name="count"></a>
## count

- `| count` - Standalone operator that returns total row count.
- Quick way to see how many rows match your filters.

**Examples**

```kql
// Simple count - total rows
EmailEvents
| where Timestamp > ago(30d)
| count
```

```kql
// Count unique users
CloudAppEvents
| where Timestamp > ago(7d)
| distinct AccountDisplayName
| count
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="numbers----" name="numbers----"></a>
<a id="comparison-operators" name="numbers"></a>
## numbers, >, <, >=, <=

- Numeric comparison operators.

**Examples**

```kql
// Files larger than 10MB
EmailAttachmentInfo
| where Timestamp >= ago(17d)
| where FileSize > 10000000
| take 10
```

```kql
// Emails with multiple attachments
EmailEvents
| where AttachmentCount >= 3
| take 10
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="ago" name="time-and-ago"></a>
<a id="ago" name="time-and-ago"></a>
## ago()

- `ago()` - Relative time from now
- Time units: `d` (days), `h` (hours), `m` (minutes), `s` (seconds)

**Examples**

```kql
// Last 7 days
EmailPostDeliveryEvents
| where Timestamp >= ago(7d)
| take 10
```

```kql
// Last 2 hours
CloudAppEvents
| where Timestamp >= ago(2h)
| take 10
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="between--datetime" name="between--datetime"></a>
<a id="between-datetime" name="between-datetime"></a>
## between / datetime

- Filter specific time ranges.

**Examples**

```kql
// Specific date range
EmailEvents
| where Timestamp between (datetime(2026-01-01) .. datetime(2026-01-07))
| take 10
```

```kql
// Between 3 days ago and 1 day ago
CloudAppEvents
| where Timestamp between (ago(3d) .. ago(1d))
| take 10
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="time-formats" name="time-formats"></a>
<a id="time-formats" name="time-formats"></a>
## Time Formats

- KQL supports ISO8601 datetime.

**Examples**

```kql
print dt = datetime(2026-01-07T13:00:00Z)
```

```kql
print pastWeek = ago(7d), pastHour = ago(1h), past30Min = ago(30m)
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="now" name="now-and-utc"></a>
<a id="now" name="now-and-utc"></a>
## now()

- `now()` returns current UTC time.
- All Advanced Hunting timestamps are UTC.
- Threat Explorer (UI) does detect timezone and display it in local timezone

**Examples**

```kql
print CurrentTime = now()
```

```kql
// How long ago was each sign-in?
IdentityLogonEvents
| where Timestamp > ago(1d)
| extend HoursAgo = datetime_diff('hour', now(), Timestamp)
| project Timestamp, HoursAgo, AccountUpn, Application
| take 5
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="top" name="top"></a>
## top

- Returns the top N rows sorted by a column.
- Combines `sort by` and `take` in one operator.

---

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

```kql
// Top domains - distinct list
EmailEvents
| distinct SenderFromDomain
| take 5
```

```kql
// Active apps - distinct list
IdentityLogonEvents
| where Timestamp > ago(7d)
| distinct Application
| take 10
```

```kql
// Users with delete actions
CloudAppEvents
| where Timestamp >= ago(30d)
| where ActionType == "SoftDelete"
| extend UserId = tostring(RawEventData.UserId)
| project UserId, Timestamp
| distinct UserId
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="extend" name="extend"></a>
## extend

- Adds new calculated columns to your results.
- Original columns are preserved.

---

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

```kql
// Convert ; round by 2 decimal
EmailAttachmentInfo
| extend FileSizeKB = round(FileSize / 1024.0, 2)
| extend FileSizeMB = round(FileSize / 1024.0 / 1024.0, 2)
| project FileName, FileType, FileSize, FileSizeKB, FileSizeMB
| sample 20
```

```kql
EmailAttachmentInfo
| extend FileNameLower = tolower(FileName)
| project FileName, FileNameLower
| take 5
```

```kql
EmailUrlInfo
| extend DomainAndLocation = strcat(UrlDomain, " (", UrlLocation, ")")
| project DomainAndLocation
| sample 10
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="live-scenario-emailattachmentinfo" name="live-scenario-emailattachmentinfo"></a>
<a id="live-scenario-emailattachmentinfo" name="live-scenario-emailattachmentinfo"></a>
## Live Scenario: EmailAttachmentInfo

<a id="scenario" name="scenario"></a>
### Scenario
Your security team received intelligence that threat actors are using `.iso`, `.vhd`, and `.img` files to deliver malware.

<a id="your-mission" name="your-mission"></a>
### Your Mission
Find all emails from the last 7 days with these potentially dangerous attachment types.

<a id="skills-tested" name="skills-tested"></a>
### Skills Tested
- `where` with time filter
- `in` operator
- `project` for clean output

```kql
// Try
```

```kql
EmailAttachmentInfo
| where Timestamp >= ago(7d)
| where FileExtension in (
    ".iso",
    ".vhd",
    ".img"
    )
| project SenderFromAddress, FileName, FileExtension, FileSize
```

```kql
EmailAttachmentInfo
| getschema 
```

```kql
EmailAttachmentInfo
| distinct FileExtension
```

```kql
EmailAttachmentInfo
| distinct FileName
```

```kql
// SOLUTION
EmailAttachmentInfo
| where Timestamp > ago(7d)
| where FileType in ("pdf", "jpeg", "mp4;", "asf")
| project Timestamp, RecipientEmailAddress, FileName, FileType, SHA256
| sort by Timestamp desc
```

```kql
// Count by FileType - preview for Lesson 2
EmailAttachmentInfo
| where Timestamp > ago(7d)
| where FileType in ("pdf", "jpeg", "mp4;", "asf")
| distinct FileType, FileName
| sort by FileType asc
```

```kql
EmailAttachmentInfo
| where Timestamp > ago(7d)
| where FileExtension has_all ("pdf", "html")
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="live-scenario-emailevents" name="live-scenario-emailevents"></a>
<a id="live-scenario-emailevents" name="live-scenario-emailevents"></a>
## Live Scenario: EmailEvents

<a id="scenario-2" name="scenario-2"></a>
### Scenario
Users are complaining about spam. Management wants to know which external domains are sending the most emails.

<a id="your-mission-2" name="your-mission-2"></a>
### Your Mission
Identify the top 10 external sender domains in the last 7 days.

<a id="skills-tested-2" name="skills-tested-2"></a>
### Skills Tested
- `where` with time and direction filter
- `distinct` for unique values
- `top`

```kql
// Try
```

```kql
EmailEvents
| where Timestamp >= ago(7d)
| where EmailDirection == "Inbound"
| distinct SenderFromDomain
```

```kql
EmailEvents
| where SenderFromDomain contains "groupon"
| project SenderFromDomain, SenderMailFromDomain, SenderFromAddress, SenderMailFromAddress
```

```kql
// Top sender domains - using distinct
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound"
| distinct SenderFromDomain
| take 10
```

```kql
EmailEvents
| where Timestamp >= ago(1d)
| where EmailDirection == "Inbound"
| summarize Count = count() by SenderMailFromDomain
| sort by Count
```

```kql
// Exclude known trusted domains
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound"
| where SenderFromDomain !in ("microsoft.com", "google.com", "outlook.com")
| distinct SenderFromDomain, SenderFromAddress
| sort by SenderFromDomain
| take 20
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="live-scenario-cloudappevents" name="live-scenario-cloudappevents"></a>
## Live Scenario: CloudAppEvents

<a id="scenario-3" name="scenario-3"></a>
### Scenario
Your manager wants a quick report of user activity in cloud applications. Which apps are most active? What actions are users taking?

<a id="your-mission-3" name="your-mission-3"></a>
### Your Mission
1. Find the top 10 applications by activity count
2. Find the most common action types

<a id="skills-tested-3" name="skills-tested-3"></a>
### Skills Tested
- `CloudAppEvents` table
- `distinct` for unique values
- `top`

```kql
//  Try
```

```kql
CloudAppEvents
| getschema 
```

```kql
CloudAppEvents
| take 1
```

```kql
CloudAppEvents
| distinct Application
```

```kql
// Top applications - distinct list
CloudAppEvents
| where Timestamp > ago(7d)
| distinct Application
| take 10
```

```kql
// Most common action types - distinct list
CloudAppEvents
| where Timestamp > ago(7d)
| distinct ActionType
| take 10
```

```kql
// Users and their apps
CloudAppEvents
| where Timestamp > ago(7d)
| distinct AccountDisplayName, Application
| sort by AccountDisplayName
| take 20
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="live-scenario-urlclickevents" name="live-scenario-urlclickevents"></a>
## Live Scenario: UrlClickEvents

<a id="scenario-4" name="scenario-4"></a>
### Scenario
Safe Links has been blocking suspicious URLs, but you want to identify users who clicked through warnings despite the risk.

<a id="your-mission-4" name="your-mission-4"></a>
### Your Mission
1. Find all blocked clicks in the last 7 days
2. Identify users who clicked through warnings
3. Correlate with email details

<a id="skills-tested-4" name="skills-tested-4"></a>
### Skills Tested
- `UrlClickEvents` table
- Filtering by `ActionType` and `IsClickedThrough`
- `sort by` and `take`

```kql
// try
```

```kql
// SOLUTION: Blocked clicks - who and what threats
UrlClickEvents
| where Timestamp > ago(7d)
| where ActionType == "ClickBlocked"
| project AccountUpn, ThreatTypes, Url
| distinct AccountUpn, ThreatTypes
| sort by AccountUpn
| take 10
```

```kql
// SOLUTION: Users who clicked through warnings
UrlClickEvents
| where Timestamp > ago(7d)
| where IsClickedThrough == true
| project AccountUpn, Url, Timestamp
| distinct AccountUpn, Url
| sort by AccountUpn
```

```kql
// Join with EmailEvents for full context
UrlClickEvents
| where Timestamp > ago(7d)
| where IsClickedThrough == true or ActionType == "ClickBlocked"
| join kind=leftouter EmailEvents on NetworkMessageId
| project 
    ClickTime = Timestamp,
    User = AccountUpn,
    Url,
    ActionType,
    ClickedThrough = IsClickedThrough,
    EmailSubject = Subject,
    Sender = SenderFromAddress
| take 20
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="live-scenario-emailpostdeliveryevents" name="live-scenario-emailpostdeliveryevents"></a>
## Live Scenario: EmailPostDeliveryEvents

<a id="scenario-5" name="scenario-5"></a>
### Scenario
Your SOC wants to understand how effective Zero-hour Auto Purge (ZAP) has been at catching threats that bypassed initial detection.

<a id="your-mission-5" name="your-mission-5"></a>
### Your Mission
1. Find all ZAP actions in the last 7 days
2. Identify which threat types triggered ZAP
3. Find the most affected users

<a id="skills-tested-5" name="skills-tested-5"></a>
### Skills Tested
- `EmailPostDeliveryEvents` table
- Filtering by `ActionType`
- `distinct` and filtering

```kql
// try
```

```kql
// SOLUTION: ZAP actions - what types exist
EmailPostDeliveryEvents
// | where Timestamp > ago(7d)
| where ActionType contains "ZAP"
| distinct ActionType, ThreatTypes
| sort by ActionType
```

```kql
// SOLUTION: Users affected by ZAP
EmailPostDeliveryEvents
// | where Timestamp > ago(7d)
| where ActionType contains "ZAP"
| project RecipientEmailAddress, ActionType, ThreatTypes
| distinct RecipientEmailAddress, ActionType
| sort by RecipientEmailAddress
| take 10
```

```kql
// ZAP timeline - when do threats get caught?
EmailPostDeliveryEvents
// | where Timestamp > ago(7d)
| where ActionType has "ZAP"
| join kind=leftouter EmailEvents on NetworkMessageId
| extend HoursToZAP = datetime_diff('hour', Timestamp, Timestamp1)
| project ActionType, HoursToZAP, RecipientEmailAddress
| sort by HoursToZAP desc
| take 20
```

[back to top](#kql-for-email-security-beginner-series)

---

<a id="common-gotchas--tips" name="common-gotchas--tips"></a>
<a id="common-gotchas-tips" name="common-gotchas-tips"></a>
## Common Gotchas & Tips

<a id="1-has-vs-contains-performance-matters" name="1-has-vs-contains-performance-matters"></a>
### 1. `has` vs `contains` - Performance Matters!
- `has` uses **term indexing** (fast!) - matches whole words/tokens
- `contains` does **substring scan** (slow!) - matches anywhere in string

<a id="2-case-sensitivity" name="2-case-sensitivity"></a>
### 2. Case Sensitivity
- `==` is case-sensitive
- `=~` is case-insensitive
- `has` is case-insensitive by default
- `has_cs` is case-sensitive

<a id="3-data-retention" name="3-data-retention"></a>
### 3. Data Retention
- Advanced Hunting retains data for **30 days** by default
- Queries beyond this will return no results

<a id="4-always-filter-by-time-first" name="4-always-filter-by-time-first"></a>
### 4. Always Filter by Time First
- Put `| where Timestamp > ago(Xd)` early in your query
- This dramatically improves performance

```kql
// GOTCHA: has vs contains performance
// FAST - uses term index (whole word match)
EmailEvents
| where Subject has "invoice"
| take 5
```

```kql
// SLOWER - substring scan
EmailEvents
| where Subject contains "invoice"
| take 5
```

```kql
// GOTCHA: Case sensitivity
// This won't match "gmail.com"
EmailEvents
| where SenderFromDomain == "GMAIL.COM"
| take 1
```

```kql
// Case-insensitive match with =~
EmailEvents
| where SenderFromDomain =~ "GMAIL.COM"
| take 1
```

[back to top](#kql-for-email-security-beginner-series)

---
