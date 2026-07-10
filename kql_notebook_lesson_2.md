<a id="kql-intermediate-series" name="kql-intermediate-series"></a>
# Microsoft Defender Advanced Hunting with KQL: Intermediate

Building on foundational concepts with aggregations, joins, and variables.

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

1. [summarize](#summarize)
2. [count()](#count)
3. [countif() / sumif() / dcountif()](#countif)
4. [min() / max()](#min-max)
5. [make_set() / make_list() / make_bag()](#make_set)
6. [dcount() / count_distinct()](#dcount)
7. [arg_max() / arg_min()](#arg_max-arg_min)
8. [take_any()](#take-any)
9. [bin()](#bin)
10. [render](#render)
11. [datetime_diff()](#datetime_diff)
12. [let](#let)
13. [Type conversion functions](#type-conversion)
14. [pack_array() / bag_pack()](#pack_array-bag_pack)
15. [join](#join)
16. [union](#union)
17. [externaldata](#externaldata)
18. [lookup](#lookup)
19. [iif() / case()](#iif)
20. [parse_json()](#parse_json)
21. [isempty() / isnull()](#isempty-isnull)
22. [coalesce()](#coalesce)
23. [Live scenario: join](#live-scenario-join)
24. [Live scenario: bin() and render](#live-scenario-bin-render)
25. [Common gotchas & tips](#common-gotchas-tips)
---

<a id="summarize" name="summarize"></a>
## summarize

- Groups rows and calculates aggregations.
- Common functions: `count()`, `dcount()`, `sum()`, `avg()`, `min()`, `max()`

**How `summarize` works**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
Before: Individual rows
┌─────────────────┬─────────────┬──────────┐
│ SenderDomain    │ Subject     │ Size     │
├─────────────────┼─────────────┼──────────┤
│ gmail.com       │ Invoice     │ 1000     │
│ outlook.com     │ Meeting     │ 2000     │
│ gmail.com       │ Payment     │ 1500     │
│ gmail.com       │ Hello       │ 500      │
│ outlook.com     │ Report      │ 3000     │
└─────────────────┴─────────────┴──────────┘
                    │
  | summarize Count = count(), TotalSize = sum(Size) by SenderDomain
                    │
                    ▼
After: Grouped aggregations
┌─────────────────┬───────┬───────────┐
│ SenderDomain    │ Count │ TotalSize │
├─────────────────┼───────┼───────────┤
│ gmail.com       │ 3     │ 3000      │
│ outlook.com     │ 2     │ 5000      │
└─────────────────┴───────┴───────────┘
</pre>

**Examples**

```kusto
EmailEvents
| where Timestamp >= ago(14d)
| where RecipientEmailAddress == "user@contoso.com" // VIP user
| summarize 
    Count = count() 
    by SenderFromAddress
| top 20 by Count desc
```

```kusto
// Count emails by sender domain
EmailEvents                          // Query the EmailEvents table
| where Timestamp > ago(7d)          // Limit to events from the last 7 days
| summarize                          // Aggregate by sender domain
    EmailCount = count()             // Total number of emails per domain
    by SenderFromDomain              // One row per sender domain
| top 20 by EmailCount desc          // top does both sort and take
// | sort by EmailCount desc
// | take 20
```

```kusto
// Count attachments by file extension
EmailAttachmentInfo                  // Query email attachment metadata
| where Timestamp > ago(7d)          // Limit to attachments from the last 7 days
| summarize                          // Aggregate by file extension
    AttachmentCount = count()        // Total number of attachments per file extension
    by FileExtension                      // One row per file extension
| sort by AttachmentCount desc       // Sort by attachment volume
| take 10                            // Return top 10 file extensions
// | top 10 by AttachmentCount desc
```

```kusto
// Largest attachment senders (files > 5 MB, last 14 days)
EmailAttachmentInfo                                             // Query email attachment metadata
| where Timestamp > ago(7d)                                    // Limit to attachments from the last 14 days
| where FileSize > 5000000                                      // Only include attachments larger than 5 MB
| summarize                                                     // Aggregate by sender
    TotalSizeBytes = sum(FileSize),                             // Total attachment size sent (bytes)
    AttachmentCount = count()                                   // Number of large attachments sent
    by SenderFromAddress                                        // One row per sender
| extend                                                        // Add calculated size in MB for readability
    TotalSizeMB = round(TotalSizeBytes / 1024.0 / 1024.0, 2)
| sort by TotalSizeBytes desc                                   // Sort by total attachment size sent
| take 10                                                       // Return top 10 senders
// | top 10 by AttachmentCount desc
```

```kusto
// Multiple aggregations in one query
EmailEvents                                         // Query the EmailEvents table
| where Timestamp > ago(7d)                         // Limit to events from the last 7 days
| summarize                                         // Aggregate multiple metrics by sender domain
    TotalEmails   = count(),                        // Total emails sent
    UniqueSenders = dcount(SenderFromAddress),      // Distinct sender addresses
    FirstSeen     = min(Timestamp),                 // Earliest email timestamp
    LastSeen      = max(Timestamp)                  // Most recent email timestamp
    by SenderFromDomain                             // One row per sender domain
| top 10 by TotalEmails                             // Return top 10 domains by email volume
```

```kusto
// avg() - average file size by extension
EmailAttachmentInfo                             // Query email attachment metadata
| where Timestamp > ago(14d)                     // Limit to attachments from the last 7 days
| summarize                                     // Aggregate size statistics by file extension
    AvgSize = round(avg(FileSize), 3),          // Average attachment size (bytes)
    MinSize = min(FileSize),                    // Smallest attachment size
    MaxSize = max(FileSize)                     // Largest attachment size
    by FileExtension                            // One row per file extension
| sort by AvgSize                               // Sort by average attachment size
| take 10                                       // Return top 10 file extensions
```

```kusto
// Count alerts by severity — simple summarize
AlertInfo
// | where Timestamp > ago(7d)
| summarize
    AlertCount = count()
    by Severity
| sort by AlertCount desc
```

```kusto
// Count Entra sign-in failures by application
EntraIdSignInEvents
| where Timestamp > ago(7d)
| where ErrorCode != 0
| summarize
    FailureCount  = count(),
    DistinctUsers = dcount(AccountUpn)
    by Application
| sort by FailureCount desc
```

```kusto
// Count URL clicks by action type
UrlClickEvents
// | where Timestamp > ago(7d)
| summarize
    ClickCount = count()
    by ActionType
| sort by ClickCount desc
```

```kusto
// Post-delivery action summary
EmailPostDeliveryEvents
// | where Timestamp > ago(7d)
| summarize
    EventCount = count(),
    AffectedMessages = dcount(NetworkMessageId)
    by ActionType
| sort by EventCount desc
```

```kusto
// Teams message threat summary by sender
MessageEvents
// | where Timestamp > ago(7d)
| where ThreatTypes != ""
| summarize
    ThreatCount = count(),
    DistinctThreats = dcount(ThreatTypes)
    by SenderEmailAddress
| sort by ThreatCount desc
```

```kusto
// URL info summary — top domains in email
EmailUrlInfo
// | where Timestamp > ago(7d)
| summarize
    UrlCount   = count(),
    MsgCount   = dcount(NetworkMessageId)
    by UrlDomain
| top 20 by UrlCount desc
```

[back to top](#kql-intermediate-series)

---

<a id="count" name="count"></a>
## count()

- Aggregation function; counts the number of rows or items.
- Used inside `summarize`. Only valid in aggregation context.

**Examples**

```kusto
EmailEvents
| where RecipientEmailAddress == "mike.taylor@contoso.com"
| where DeliveryLocation has "Inbox"
| summarize Count = count() by SenderFromDomain
```

```kusto
EmailAttachmentInfo
| where isnotempty(FileName)
| summarize FileCount = count()
```

```kusto
// EmailEvents
// | count 
EmailEvents
| summarize Count = count()
```

```kusto
// Count high-severity alerts in the last 7 days
AlertInfo
// | where Timestamp > ago(7d)
| where Severity == "High"
| summarize count()
```

```kusto
// Count Entra sign-in failures in last 24 hours
EntraIdSignInEvents
| where Timestamp > ago(1d)
| where ErrorCode != 0
| summarize FailureCount = count()
```

```kusto
// Count URL clicks in last 7 days
UrlClickEvents
// | where Timestamp > ago(7d)
| summarize count()
```

```kusto
// Count post-delivery events (e.g. ZAP actions)
EmailPostDeliveryEvents
// | where Timestamp > ago(7d)
| summarize count()
```

[back to top](#kql-intermediate-series)

---

<a id="countif" name="countif"></a>
## countif() / sumif() / dcountif()

- Conditional aggregations inside `summarize`.
- `countif()` — count only where condition is true.
- `sumif()` — sum values only where condition is true.
- `dcountif()` — count distinct values only where condition is true.
- Allows multiple filtered aggregations in one query.

**How conditional aggregations work**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
Example:

Before: Email delivery data
┌─────────────┬──────────────────┐
│ ActionType  │ DeliveryLocation │
├─────────────┼──────────────────┤
│ Delivered   │ Inbox            │  ← countif(DeliveryLocation == "Inbox")
│ Delivered   │ Junk             │
│ Blocked     │ Quarantine       │  ← countif(ActionType == "Blocked")
│ Delivered   │ Inbox            │  ← countif(DeliveryLocation == "Inbox")
│ Delivered   │ Junk             │
└─────────────┴──────────────────┘
                    │
    | summarize 
        InboxCount = countif(DeliveryLocation == "Inbox"),
        BlockedCount = countif(ActionType == "Blocked"),
        TotalCount = count()
                    │
                    ▼
After: Aggregated counts
┌────────────┬──────────────┬────────────┐
│ InboxCount │ BlockedCount │ TotalCount │
├────────────┼──────────────┼────────────┤
│ 2          │ 1            │ 5          │
└────────────┴──────────────┴────────────┘
</pre>

**Examples**

```kusto
EmailEvents                                                         // Query the EmailEvents table
| where RecipientEmailAddress == "user@contoso.com"                 // Filter to a specific recipient mailbox
| summarize                                                         // Aggregate email delivery results into time buckets
    InboxDelivered = countif(DeliveryLocation contains "Inbox")     // Count messages delivered to Inbox
    by bin(Timestamp, 1h)                                           // Group results into 1-hour time bins
```

```kusto
EmailEvents                                                 // Query the EmailEvents table
| where Timestamp > ago(7d)
| summarize                                                 // Aggregate by sender domain
    Total = count(),                                        // Total messages from this sender
    WithAttachments = countif(AttachmentCount > 0)          // Messages that included at least one attachment
    by SenderFromDomain                                     // One row per sender domain
| top 20 by Total desc
```

```kusto
IdentityLogonEvents                                         // Query identity logon events
| summarize                                                 // Aggregate authentication results by application
    FailedLogons = countif(ActionType == "LogonFailed")     // Count failed sign-in attempts
    by Application                                          // One row per application
```

```kusto
// Count high vs medium vs low alerts in a single pass
AlertInfo
// | where Timestamp > ago(7d)
| summarize
    HighCount   = countif(Severity == "High"),
    MediumCount = countif(Severity == "Medium"),
    LowCount    = countif(Severity == "Low"),
    InfoCount   = countif(Severity == "Informational")
```

```kusto
// Count Entra sign-in successes vs failures per app
EntraIdSignInEvents
| where Timestamp > ago(7d)
| summarize
    Successes = countif(ErrorCode == 0),
    Failures  = countif(ErrorCode != 0)
    by Application
| sort by Failures desc
```

```kusto
// Count blocked clicks vs click-throughs per user
UrlClickEvents
// | where Timestamp > ago(7d)
| summarize
    Blocked      = countif(ActionType == "ClickBlocked"),
    ClickedThru  = countif(IsClickedThrough == true)
    by AccountUpn
| where Blocked > 0 or ClickedThru > 0
| sort by Blocked desc
```

```kusto
// Count ZAP vs manual remediation post-delivery actions
EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| summarize
    ZapActions    = countif(ActionType has "ZAP"),
    ManualActions = countif(ActionType has "Manual")
```

```kusto
// Compare inbound vs outbound email sizes
EmailEvents                                          // Query the EmailEvents table
| where Timestamp > ago(7d)                          // Limit to last 7 days
| summarize                                          // Multiple conditional aggregations
    TotalEmails = count(),                           // All emails
    InboundCount = countif(EmailDirection == "Inbound"),
    OutboundCount = countif(EmailDirection == "Outbound"),
    InboundWithAttachments = countif(EmailDirection == "Inbound" and AttachmentCount > 0),
    OutboundWithAttachments = countif(EmailDirection == "Outbound" and AttachmentCount > 0)
```

```kusto
// Sum attachment sizes by file type category
EmailAttachmentInfo                                  // Query attachment metadata
| where Timestamp > ago(7d)                          // Limit to last 7 days
| summarize                                          // Conditional sums by file type
    TotalSize = sum(FileSize),                       // All attachments
    ExeSize = sumif(FileSize, FileType == "exe"),    // Executable files
    PdfSize = sumif(FileSize, FileType == "pdf"),    // PDF files
    DocSize = sumif(FileSize, FileType contains "doc"),   // Word documents
    ZipSize = sumif(FileSize, FileType in ("zip", "rar", "7z"))  // Archives
| extend                                             // Calculate percentages
    ExePct = round(100.0 * ExeSize / TotalSize, 2),
    PdfPct = round(100.0 * PdfSize / TotalSize, 2)
```

```kusto
// Count unique senders by threat category
EmailEvents                                          // Query the EmailEvents table
| where Timestamp > ago(30d)                         // Limit to last 30 days
| summarize                                          // Conditional distinct counts
    TotalUniqueSenders = dcount(SenderFromAddress),
    InboxSenders = dcountif(SenderFromAddress, DeliveryLocation == "Inbox"),
    JunkSenders = dcountif(SenderFromAddress, DeliveryLocation == "JunkFolder"),
    QuarantinedSenders = dcountif(SenderFromAddress, DeliveryLocation == "Quarantine")
```

```kusto
// Count distinct users with failures vs successes in Entra
EntraIdSignInEvents
| where Timestamp > ago(7d)
| summarize
    UsersWithFailures = dcountif(AccountUpn, ErrorCode != 0),
    UsersWithSuccess  = dcountif(AccountUpn, ErrorCode == 0)
```

```kusto
// Count distinct alert titles by severity
AlertInfo
| where Timestamp > ago(7d)
| summarize
    UniqueHighAlerts   = dcountif(Title, Severity == "High"),
    UniqueMediumAlerts = dcountif(Title, Severity == "Medium")
```

```kusto
// Count distinct URLs by click outcome
UrlClickEvents
| where Timestamp > ago(7d)
| summarize
    UniqueBlockedUrls = dcountif(Url, ActionType == "ClickBlocked"),
    UniqueClickedUrls = dcountif(Url, IsClickedThrough == true)
```

[back to top](#kql-intermediate-series)

---

<a id="min-max" name="min-max"></a>
## min() / max()

- Returns smallest (`min()`) or largest (`max()`) value.
- Common in timestamp or numerical analysis.

**Examples**

```kusto
IdentityLogonEvents                 // Query the IdentityLogonEvents table (each row = a sign-in event)
| summarize                         // Aggregate across all events in the dataset 
    FirstSeen = min(Timestamp),     // Earliest timestamp in the entire dataset
    LastSeen  = max(Timestamp)      // Most recent timestamp in the entire dataset
```

```kusto
EmailEvents                         // Query the EmailEvents table (each row represents a single email event)
| summarize                         // Aggregate events by sender domain
    Earliest = min(Timestamp),      // Earliest email timestamp observed for each sender domain
    Latest   = max(Timestamp)       // Most recent email timestamp observed for each sender domain
    by SenderFromDomain             // Group results so each row represents one sender domain
```

```kusto
EmailAttachmentInfo
| where Timestamp > ago (14d)
| summarize LargestFile = max(FileSize) 
    by FileType
```

```kusto
// Earliest and latest alert per category
AlertInfo
| where Timestamp > ago(30d)
| summarize
    FirstSeen = min(Timestamp),
    LastSeen  = max(Timestamp)
    by Category
| sort by LastSeen desc
```

```kusto
// First and last Entra sign-in failure per user
EntraIdSignInEvents
| where Timestamp > ago(30d)
| where ErrorCode != 0
| summarize
    FirstFailure = min(Timestamp),
    LastFailure  = max(Timestamp)
    by AccountUpn
| sort by LastFailure desc
```

```kusto
// First and last URL click per user
UrlClickEvents
| where Timestamp > ago(30d)
| summarize
    FirstClick = min(Timestamp),
    LastClick  = max(Timestamp)
    by AccountUpn
| sort by LastClick desc
```

```kusto
// First and last post-delivery action per message
EmailPostDeliveryEvents
| where Timestamp > ago(14d)
| summarize
    FirstAction = min(Timestamp),
    LastAction  = max(Timestamp)
    by NetworkMessageId
| sort by LastAction desc
```

```kusto
// avg() — average file size by extension
EmailAttachmentInfo
| where Timestamp > ago(7d)
| summarize AvgSize = round(avg(FileSize), 3) by FileExtension
| sort by AvgSize desc
| take 10
```

[back to top](#kql-intermediate-series)

---

<a id="make_set" name="make_set"></a>
## make_set() / make_list() / make_bag()

All three collect values from multiple rows into a single cell within `summarize`.

### make_set()

- Creates an array of unique values.
- Useful for grouping unique domains, users, or actions.

**How `make_set()` works**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
Before: Multiple rows per sender
┌─────────────────┬─────────────────────┐
│ Sender          │ Recipient           │
├─────────────────┼─────────────────────┤
│ alice@contoso   │ bob@fabrikam        │
│ alice@contoso   │ carol@fabrikam      │
│ alice@contoso   │ bob@fabrikam        │  ← duplicate
│ alice@contoso   │ dan@fabrikam        │
└─────────────────┴─────────────────────┘
                  │
    summarize make_set(Recipient) by Sender
                  │
                  ▼
After: One row with unique array
┌─────────────────┬───────────────────────────────────────────┐
│ Sender          │ Recipients                                │
├─────────────────┼───────────────────────────────────────────┤
│ alice@contoso   │ ["bob@fabrikam","carol@fabrikam","dan@.."]│
└─────────────────┴───────────────────────────────────────────┘
</pre>

**Examples**

```kusto
EmailEvents                                         // Query the EmailEvents table
| summarize                                         // Aggregate by sender address
    Recipients = make_set(RecipientEmailAddress)    // Collect unique recipient addresses per sender
    by SenderFromAddress                            // One row per sender address
```

```kusto
CloudAppEvents
| distinct Application, ActionType
```

```kusto
CloudAppEvents                              // Query cloud application activity events
| summarize                                 // Aggregate by application
    ActionTypes = make_set(ActionType)      // Collect unique action types per application
    by Application                          // One row per application
```

```kusto
CloudAppEvents
| where ActionType == "TabAdded"
| sample 5
```

```kusto
EmailEvents                                 // Query the EmailEvents table
| where RecipientEmailAddress == "user@contoso.com"
| summarize                                 // Aggregate by sender address
    SenderIPs = make_set(SenderIPv4)        // Collect unique IPv4 sender IPs per sender
    by SenderFromAddress                    // One row per sender address
```

```kusto
// Collect unique alert categories per severity level
AlertInfo
| where Timestamp > ago(7d)
| summarize
    Categories = make_set(Category)
    by Severity
```

```kusto
// Collect unique apps accessed per user in Entra sign-ins
EntraIdSignInEvents
| where Timestamp > ago(7d)
| summarize
    Apps = make_set(Application)
    by AccountUpn
| sort by array_length(Apps) desc
```

```kusto
// Collect unique URL domains per email message
EmailUrlInfo
| where Timestamp > ago(7d)
| summarize
    Domains = make_set(UrlDomain)
    by NetworkMessageId
```

```kusto
// Collect unique URLs clicked per user
UrlClickEvents
| where Timestamp > ago(7d)
| summarize
    UrlsClicked = make_set(Url)
    by AccountUpn
```

### make_list()

- Creates an array of all values (including duplicates).
- Use when you need to preserve duplicates. Row order in the list matches input row order — sort before `summarize` if you need a specific order.

**make_set() vs make_list()**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
Before: Multiple rows per sender
┌─────────────────┬─────────────────────┐
│ Sender          │ Recipient           │
├─────────────────┼─────────────────────┤
│ alice@contoso   │ bob@fabrikam        │
│ alice@contoso   │ carol@fabrikam      │
│ alice@contoso   │ bob@fabrikam        │  ← duplicate
│ alice@contoso   │ bob@fabrikam        │  ← duplicate
└─────────────────┴─────────────────────┘
                  │
                  ▼
    make_set(Recipient)  → ["bob@fabrikam","carol@fabrikam"]  (unique)
    make_list(Recipient) → ["bob@fabrikam","carol@fabrikam",  (all)
                            "bob@fabrikam","bob@fabrikam"]
</pre>

**Examples**

```kusto
EmailEvents                                             // Query the EmailEvents table
| summarize                                             // Aggregate by sender address
    AllRecipients = make_list(RecipientEmailAddress)    // Collect all recipient addresses (duplicates included)
    by SenderFromAddress                                // One row per sender address
| take 5
```

```kusto
EmailEvents                                                 // Query the EmailEvents table
| where Timestamp > ago(1d)                                 // Limit to events from the last 1 day
| summarize                                                 // Aggregate recipient data by sender address
    UniqueRecipients = make_set(RecipientEmailAddress),     // Unique recipient addresses (deduplicated)
    AllRecipients    = make_list(RecipientEmailAddress)     // All recipient addresses (duplicates preserved)
    by SenderFromAddress                                    // One row per sender address
| take 5
```

```kusto
// List all alert titles per category (duplicates preserved)
AlertInfo
| where Timestamp > ago(7d)
| summarize
    AllTitles = make_list(Title)
    by Category
```

```kusto
// List every URL a user clicked this week (with repeats)
UrlClickEvents
| where Timestamp > ago(7d)
| summarize
    UniqueUrls = make_set(Url),
    AllUrls    = make_list(Url)
    by AccountUpn
```

```kusto
// List all action types per post-delivery message (ordered)
EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| sort by NetworkMessageId asc, Timestamp asc  // make_list() preserves row order — sort first to control list order
| summarize
    ActionList = make_list(ActionType)
    by NetworkMessageId
```

### make_bag()

- Collects key-value pairs into a JSON object.
- Produces a named JSON object — access values by key instead of by index, unlike the positional arrays from `make_set()` and `make_list()`.
- Combines with `summarize` to create one JSON object per group.

**How `make_bag()` works**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
Before: Multiple rows per sender
┌─────────────────┬─────────────┬─────────────┐
│ Sender          │ Property    │ Value       │
├─────────────────┼─────────────┼─────────────┤
│ alice@contoso   │ Department  │ Sales       │
│ alice@contoso   │ Location    │ Seattle     │
│ alice@contoso   │ Role        │ Manager     │
└─────────────────┴─────────────┴─────────────┘
                  │
    summarize make_bag(bag_pack(Property, Value)) by Sender
                  │
                  ▼
After: One row with JSON object
┌─────────────────┬──────────────────────────────────────────────┐
│ Sender          │ Properties                                   │
├─────────────────┼──────────────────────────────────────────────┤
│ alice@contoso   │ {"Department":"Sales","Location":"Seattle",  │
│                 │  "Role":"Manager"}                           │
└─────────────────┴──────────────────────────────────────────────┘
</pre>

**Examples**

```kusto
// Collect email metadata into a single JSON object per message
EmailEvents                                          // Query the EmailEvents table
| where Timestamp > ago(7d)                          // Limit to last 7 days
| where RecipientEmailAddress == "user@contoso.com"
| extend                                             // Create key-value pair for each row
    EmailDetail = bag_pack(                              // Pack fields into JSON object
        "Subject", Subject,
        "Direction", EmailDirection,
        "Location", DeliveryLocation
    )
| summarize                                          // Aggregate by sender
    EmailBag = make_bag(EmailDetail)                 // Merge JSON objects into one bag
    by SenderFromAddress                             // One row per sender
| take 10
```

```kusto
// Aggregate attachment details into a property bag per message
EmailAttachmentInfo                                  // Query email attachment metadata
| where Timestamp > ago(7d)                          // Limit to last 7 days
| extend                                             // Create key-value pair using filename as key
    FileDetail = bag_pack(FileName, FileSize)            // Pack filename → size mapping
| summarize                                          // Aggregate by message
    AttachmentBag = make_bag(FileDetail)             // Merge into single JSON object
    by NetworkMessageId                              // One row per message
| take 10
```

```kusto
// Aggregate user actions per application
CloudAppEvents                                       // Query cloud application events
| where Timestamp > ago(7d)                          // Limit to last 7 days
| extend                                             // Create action → object mapping
    ActionMapping = bag_pack(                            // Pack action details
        ActionType,                                  // Action type as key
        ObjectName                                   // Object affected as value
    )
| summarize                                          // Aggregate by user and app
    ActionsBag = make_bag(ActionMapping)             // Merge into single JSON object
    by AccountDisplayName, Application               // One row per user per app
| sample 10
```

```kusto
// Aggregate post-delivery actions and results per message
EmailPostDeliveryEvents                              // Query post-delivery events
| where Timestamp > ago(7d)                          // Limit to last 7 days
| where ActionType != "Dynamic Delivery"
| extend                                             // Create action details mapping
    ActionMapping = bag_pack(                            // Pack action details
        "Action", Action,                            // Action taken on the entity
        "ActionType", ActionType,                    // Type (ZAP, Manual remediation)
        "ActionTrigger", ActionTrigger,              // What triggered it (Admin, ZAP, etc.)
        "ActionResult", ActionResult                 // Result (Success, Error)
    )
| summarize                                          // Aggregate by message and recipient
    ActionsBag = make_bag(ActionMapping)             // Merge into single JSON object
    by NetworkMessageId, RecipientEmailAddress       // One row per message per recipient
| sample 10
```

```kusto
// Property bag of entity types and roles per alert
AlertEvidence
| where Timestamp > ago(7d)
| extend
    EvidenceDetail = bag_pack(
        "EntityType",  EntityType,
        "EvidenceRole", EvidenceRole
    )
| summarize
    EvidenceBag = make_bag(EvidenceDetail)
    by AlertId
```

```kusto
// Bag of sign-in failure details per user
EntraIdSignInEvents
| where Timestamp > ago(7d)
| where ErrorCode != 0
| extend
    FailureDetail = bag_pack(
        Application, ErrorCode
    )
| summarize
    FailureBag = make_bag(FailureDetail)
    by AccountUpn
```

```kusto
// URL click details per user — action → URL mapping
UrlClickEvents
| where Timestamp > ago(7d)
| extend
    ClickDetail = bag_pack(
        ActionType, Url
    )
| summarize
    ClickBag = make_bag(ClickDetail)
    by AccountUpn
```

> `bag_pack()` builds a named JSON object from field values. `make_bag()` aggregates those objects across multiple rows into one combined JSON object. They are typically used together: `bag_pack()` per row, then `make_bag()` in a `summarize`.

**Function comparison**

| Function | Output | Dedupe | Use when |
|---|---|---|---|
| `make_set()` | Array | Yes — unique values only | You want distinct values per group |
| `make_list()` | Array | No — duplicates preserved | You need order or frequency |
| `make_bag()` | JSON object | No — key-value pairs | You want named pairs instead of an array |

[back to top](#kql-intermediate-series)

---

<a id="dcount" name="dcount"></a>
## dcount() / count_distinct()

- Counts distinct values using an approximation — fast and efficient on large datasets.
- Accurate enough for investigations and dashboards.
- For exact counts in reports or escalations, use `count_distinct()` instead.

**Examples**

```kusto
EmailEvents
| summarize UniqueSenders = dcount(SenderFromAddress)
```

```kusto
EmailAttachmentInfo
| summarize UniqueHashes = dcount(SHA256)
```

```kusto
UrlClickEvents
| summarize DistinctUsers = dcount(AccountUpn)
```

```kusto
// Count distinct alert titles in the last 7 days
AlertInfo
| where Timestamp > ago(7d)
| summarize UniqueAlertTitles = dcount(Title)
```

```kusto
// Count distinct countries with Entra sign-in failures
EntraIdSignInEvents
| where Timestamp > ago(7d)
| where ErrorCode != 0
| summarize UniqueCountries = dcount(Country)
```

```kusto
// Count distinct affected messages per post-delivery action
EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| summarize
    AffectedMessages = dcount(NetworkMessageId)
    by ActionType
| sort by AffectedMessages desc
```

```kusto
// Count distinct Teams message senders with threat detections
MessageEvents
| where Timestamp > ago(7d)
| where ThreatTypes != ""
| summarize UniqueThreatSenders = dcount(SenderEmailAddress)
```

```kusto
// Count distinct URL domains seen per recipient
EmailUrlInfo
| where Timestamp > ago(7d)
| summarize
    DistinctDomains = dcount(UrlDomain)
    by NetworkMessageId
| sort by DistinctDomains desc
```

**count_distinct() — exact distinct count**

`count_distinct(col)` returns an **exact** count of unique values — unlike `dcount()`, which uses an approximation.
Use it when accuracy matters more than performance. On large datasets it is significantly more expensive than `dcount()`.

Rule of thumb: use `dcount()` for dashboards and exploration. Use `count_distinct()` when you need a confirmed exact figure.

**Examples**

```kusto
// count_distinct() vs dcount() — exact vs approximate unique sender count
// dcount() is faster on large datasets; count_distinct() guarantees an exact result
EmailEvents
| where Timestamp > ago(7d)
| summarize
    Approx = dcount(SenderFromAddress),
    Exact  = count_distinct(SenderFromAddress)
```

```kusto
// count_distinct() — exact figures for reporting and compliance
// Use when presenting numbers to stakeholders who need verified counts
EntraIdSignInEvents
| where Timestamp > ago(30d)
| where ErrorCode != 0
| summarize
    UniqueCountries = count_distinct(Country),
    UniqueUsers     = count_distinct(AccountUpn)
| project UniqueCountries, UniqueUsers
```

[back to top](#kql-intermediate-series)

---

<a id="arg_max-arg_min" name="arg_max-arg_min"></a>
## arg_max() / arg_min()

### arg_max()

- Returns the row with the maximum value of a column — use for the latest or most recent record per group.
- Another way to view it: *"Give me the record associated with the max value."*

**How `arg_max()` works**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
Before: Multiple sign-ins per user
┌─────────────┬─────────────────────┬─────────────┐
│ AccountUpn  │ Timestamp           │ Application │
├─────────────┼─────────────────────┼─────────────┤
│ alice@co    │ 2024-01-15 09:00    │ Outlook     │
│ alice@co    │ 2024-01-15 14:30    │ Teams       │  ← MAX timestamp
│ alice@co    │ 2024-01-15 11:15    │ SharePoint  │
│ bob@co      │ 2024-01-15 08:00    │ Outlook     │
│ bob@co      │ 2024-01-15 16:45    │ Teams       │  ← MAX timestamp
└─────────────┴─────────────────────┴─────────────┘
                         │
    summarize arg_max(Timestamp, Application) by AccountUpn
                         │
                         ▼
After: Latest sign-in per user
┌─────────────┬─────────────────────┬─────────────┐
│ AccountUpn  │ Timestamp           │ Application │
├─────────────┼─────────────────────┼─────────────┤
│ alice@co    │ 2024-01-15 14:30    │ Teams       │
│ bob@co      │ 2024-01-15 16:45    │ Teams       │
└─────────────┴─────────────────────┴─────────────┘
</pre>

`arg_max(Timestamp,*)` mentally translates to: *"Give me the latest row"*

**Examples**

```kusto
IdentityLogonEvents                     // Query identity logon events
| summarize                             // Aggregate by account UPN
    max(Timestamp)               // Select the most recent event and return all columns
    by AccountUpn                       // One row per account
```

```kusto
IdentityLogonEvents                     // Query identity logon events
| summarize                             // Aggregate by account UPN
    arg_max(Timestamp, *)               // Select the most recent event and return all columns
    by AccountUpn                       // One row per account
| take 5
```

```kusto
EmailAttachmentInfo                     // Query email attachment metadata
| where Timestamp >= ago(1d)
| summarize                             // Aggregate by recipient email address
    arg_max(FileSize, FileName)         // Select the largest attachment and return its file name
    by RecipientEmailAddress            // One row per recipient
| sort by FileSize desc                 // Sort recipients by largest attachment size
```

```kusto
EmailEvents                                             // Query email events
| summarize                                             // Aggregate by message ID
    arg_max(Timestamp, Subject, SenderFromAddress)      // Select the most recent event per message
    by NetworkMessageId                                 // One row per email message
```

```kusto
CloudAppEvents                                      // Query cloud application activity events
| where Timestamp > ago (1d)
| summarize                                         // Aggregate by account object ID
    arg_max(Timestamp, ActionType, Application, RawEventData)     // Select the most recent action and app
    by AccountObjectId                              // One row per account
```

```kusto
// Most recent alert per category
AlertInfo
| where Timestamp > ago(30d)
| summarize
    arg_max(Timestamp, Title, Severity, ServiceSource)
    by Category
```

```kusto
// Most recent Entra sign-in per user (success or failure)
EntraIdSignInEvents
| where Timestamp > ago(30d)
| summarize
    arg_max(Timestamp, Application, Country, ErrorCode)
    by AccountUpn
```

```kusto
// Most recent post-delivery action per message
EmailPostDeliveryEvents
| where Timestamp > ago(14d)
| summarize
    arg_max(Timestamp, ActionType, ThreatTypes)
    by NetworkMessageId
```

```kusto
// Most recent URL click per user (last action taken)
UrlClickEvents
| where Timestamp > ago(7d)
| summarize
    arg_max(Timestamp, Url, ActionType, IsClickedThrough)
    by AccountUpn
```

### arg_min()

- Returns the row with the minimum value — use for the earliest or first record per group.
- Another way to view it: *"Give me the record associated with the min value."*

**How `arg_min()` works**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
Before: Multiple sign-ins per user
┌─────────────┬─────────────────────┬─────────────┐
│ AccountUpn  │ Timestamp           │ Application │
├─────────────┼─────────────────────┼─────────────┤
│ alice@co    │ 2024-01-15 09:00    │ Outlook     │  ← MIN timestamp
│ alice@co    │ 2024-01-15 14:30    │ Teams       │
│ alice@co    │ 2024-01-15 11:15    │ SharePoint  │
│ bob@co      │ 2024-01-15 08:00    │ Outlook     │  ← MIN timestamp
│ bob@co      │ 2024-01-15 16:45    │ Teams       │
└─────────────┴─────────────────────┴─────────────┘
                         │
    summarize arg_min(Timestamp, Application) by AccountUpn
                         │
                         ▼
After: First sign-in per user
┌─────────────┬─────────────────────┬─────────────┐
│ AccountUpn  │ Timestamp           │ Application │
├─────────────┼─────────────────────┼─────────────┤
│ alice@co    │ 2024-01-15 09:00    │ Outlook     │
│ bob@co      │ 2024-01-15 08:00    │ Outlook     │
└─────────────┴─────────────────────┴─────────────┘
</pre>

`arg_min(Timestamp,*)` mentally translates to: *"Give me the earliest row"*

**Examples**

```kusto
IdentityLogonEvents                  // Query identity logon events
| summarize                          // Aggregate by account UPN
    arg_min(Timestamp, *)            // Select the earliest sign-in event and return all columns
    by AccountUpn                    // One row per user account
```

```kusto
EmailAttachmentInfo                         // Query email attachment metadata
| summarize                                 // Aggregate by recipient email address
    arg_min(FileSize, *)   // Select the smallest attachment and return its details
    by RecipientEmailAddress                // One row per recipient
| sort by FileSize desc                      // Sort recipients by smallest attachment size
```

```kusto
// Earliest alert ever fired per category
AlertInfo
| where Timestamp > ago(90d)
| summarize
    arg_min(Timestamp, Title, Severity)
    by Category
```

```kusto
// First Entra sign-in failure per user
EntraIdSignInEvents
| where Timestamp > ago(30d)
| where ErrorCode != 0
| summarize
    arg_min(Timestamp, Application, IPAddress, ErrorCode)
    by AccountUpn
```

```kusto
// First URL a user ever clicked (earliest click on record)
UrlClickEvents
| where Timestamp > ago(30d)
| summarize
    arg_min(Timestamp, Url, ActionType)
    by AccountUpn
```

```kusto
// AiTM detection: stolen session cookie reused from a different country
// A stolen session cookie shares the original SessionId but the attacker signs in from a new country
// arg_min(Timestamp, Country) captures the first (legitimate) country for each session
let OfficeHomeSessions =
    EntraIdSignInEvents
    | where Timestamp > ago(7d) and ErrorCode == 0
        and ApplicationId == "4765445b-32c6-49b0-83e6-1d93765276ca"  // Office Home app
        and ClientAppUsed == "Browser"
    | summarize arg_min(Timestamp, Country) by SessionId;
EntraIdSignInEvents
| where Timestamp > ago(7d)
    and ApplicationId != "4765445b-32c6-49b0-83e6-1d93765276ca"
    and ClientAppUsed == "Browser"
| project OtherTimestamp = Timestamp, AccountObjectId,
    AccountDisplayName, OtherCountry = Country, SessionId
| join kind=inner OfficeHomeSessions on SessionId
| where OtherTimestamp > Timestamp   // later sign-in on same session
    and OtherCountry != Country        // from a different country
```

[back to top](#kql-intermediate-series)

---

<a id="take-any" name="take-any"></a>
## take_any()

- `take_any(col)` returns an arbitrary non-null value from the group — no ordering required.
- Use when you need one representative value per group and the exact row doesn't matter.
- Cheaper than `arg_max()` or `arg_min()` — skips the comparison step entirely.

| | `arg_max()` / `arg_min()` | `take_any()` |
|---|---|---|
| Selection criteria | Most or least recent row by key column | Any row (arbitrary) |
| Cost | Higher — requires ordering within group | Lower |
| Use when | You need the specific row with the highest or lowest value | You need any sample value per group |

**Examples**

```kusto
// take_any() — one sample subject line per sender (arbitrary, not latest)
EmailEvents
| where Timestamp > ago(7d)
| where RecipientEmailAddress == "user@contoso.com"
| summarize
    SampleSubject = take_any(Subject),
    EmailCount    = count()
    by SenderFromAddress
| sort by EmailCount desc
| take 20
```

```kusto
// take_any() — get a display name for each user in sign-in failures
EntraIdSignInEvents
| where Timestamp > ago(7d)
| where ErrorCode != 0
| summarize
    DisplayName  = take_any(AccountDisplayName),
    FailureCount = count()
    by AccountUpn
| sort by FailureCount desc
| take 20
```

[back to top](#kql-intermediate-series)

---

<a id="bin" name="bin"></a>
## bin()

- Groups values into fixed-size buckets.
- Essential for time-based aggregation and charting.

**How `bin()` works**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
Raw Timestamps                    After bin(Timestamp, 1h)
┌─────────────────────┐           ┌─────────────────────┐
│ 2024-01-15 09:05:23 │──────────>│ 2024-01-15 09:00:00 │
│ 2024-01-15 09:32:45 │──────────>│ 2024-01-15 09:00:00 │
│ 2024-01-15 09:58:12 │──────────>│ 2024-01-15 09:00:00 │
│ 2024-01-15 10:15:33 │──────────>│ 2024-01-15 10:00:00 │
│ 2024-01-15 10:45:01 │──────────>│ 2024-01-15 10:00:00 │
└─────────────────────┘           └─────────────────────┘

Common intervals: 5m, 15m, 1h, 1d, 7d
</pre>

**Examples**

```kusto
EmailEvents                          // Query the EmailEvents table
| where Timestamp > ago (7d)
| summarize                          // Aggregate events into fixed 1-hour time buckets
    MessagesPerHourBlock = count()   // Count number of email events per hour
    by bin(Timestamp, 1h)            // Group events into 1-hour time bins
| render columnchart   
```

```kusto
CloudAppEvents                       // Query cloud application activity events
| where Timestamp >= ago(14d)
| summarize                          // Aggregate events into fixed 1-day time buckets
    EventsPerDay = count()           // Count number of events per day
    by bin(Timestamp, 1d)            // Group events into 1-day time bins
| render columnchart 
```

```kusto
UrlClickEvents                       // Query URL click activity events
| summarize                          // Aggregate events into fixed 5-minute time buckets
    ClicksPer5Min = count()          // Count number of URL click events per 5-minute window
    by bin(Timestamp, 5m)            // Group events into 5-minute time bins
```

```kusto
// Alert volume by hour — detect spikes
AlertInfo
| where Timestamp > ago(7d)
| summarize
    AlertsPerHour = count()
    by bin(Timestamp, 1h)
| sort by Timestamp asc
```

```kusto
// Entra sign-in failures by day
EntraIdSignInEvents
| where Timestamp > ago(30d)
| where ErrorCode != 0
| summarize
    FailuresPerDay = count()
    by bin(Timestamp, 1d)
| sort by Timestamp asc
```

```kusto
// Post-delivery ZAP events by hour
EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| where ActionType has "ZAP"
| summarize
    ZapActionsPerHour = count()
    by bin(Timestamp, 12h)
| sort by Timestamp asc
| render barchart 
```

[back to top](#kql-intermediate-series)

---

<a id="render" name="render"></a>
## render

- Transforms tabular output into a visualization.
- Chart type is specified after `render`.  


| Chart type | Use when |
|---|---|
| `timechart` | Plotting values over time; requires a `datetime` column grouped by `bin()` |
| `barchart` | Comparing values across categories (horizontal bars) |
| `columnchart` | Same as `barchart` but rendered as vertical columns |
| `piechart` | Showing proportional breakdown of a categorical total |
| `scatterchart` | Comparing two numeric dimensions per row |
| `anomalychart` | Visualises anomaly scores from `series_decompose_anomalies()` — requires `make-series` output |

**Visual Renderings**

```kusto
| render timechart with (ysplit=panels)
```
![timechart](https://learn.microsoft.com/en-us/kusto/query/media/visualization-timechart/ysplit-panels.png?view=microsoft-fabric)

```kusto
| render barchart with (kind=stacked)
```
![anomaly](https://learn.microsoft.com/en-us/kusto/query/media/visualization-barchart/stacked-bar-chart.png?view=microsoft-fabric)

```kusto
| render columnchart with (ysplit=axes)
```
![anomaly](https://learn.microsoft.com/en-us/kusto/query/media/visualization-columnchart/column-chart-ysplit-axes.png?view=microsoft-fabric)

```kusto
| render piechart with(title="Storm Events by State")
```
![anomaly](https://learn.microsoft.com/en-us/kusto/query/media/visualization-piechart/pie-chart.png?view=microsoft-fabric)

```kusto
| render scatterchart with (xtitle="State population", title="Property damage by state", legend=hidden)
```
![scatterchart](https://learn.microsoft.com/en-us/kusto/query/media/visualization-scatterchart/scatter-chart.png?view=microsoft-fabric)

```kusto
| render anomalychart with(anomalycolumns=anomalies, title='Web app. traffic of a month, anomalies')
```
![anomaly](https://learn.microsoft.com/en-us/kusto/query/media/visualization-anomalychart/anomaly-chart.png?view=microsoft-fabric)

**Examples**

```kusto
// Email volume by hour — columnchart with two metrics on separate axes
// ysplit=axes assigns each series its own y-axis when scales differ significantly
EmailEvents
| where Timestamp >= ago(1d)
| summarize
    TotalEmails     = count(),
    WithAttachments = countif(AttachmentCount > 0)
    by bin(Timestamp, 1h)
| render columnchart with (
    title='Hourly email volume'
)
```

```kusto
// Inbound vs outbound email volume — timechart with separate panels per series
// ysplit=panels renders each series in its own horizontal panel
EmailEvents
| where Timestamp > ago(3d)
| where EmailDirection != "Unknown"
| summarize Count = count() by bin(Timestamp, 1h), EmailDirection
| render timechart with (
    title='Email volume by direction'
)
```

```kusto
// Email direction breakdown — piechart with title and visible legend
EmailEvents
| where Timestamp > ago(7d)
| summarize Count = count() by EmailDirection
| render piechart with (
    title='Email direction breakdown',
    legend=visible
)
```

```kusto
// Entra sign-in failures by country — barchart with axis labels
EntraIdSignInEvents
| where Timestamp > ago(7d)
| where ErrorCode != 0
| summarize Failures = count() by Country
| render barchart with (
    title='Sign-in failures by country',
    ytitle='Failure count',
    legend=hidden
)
```

```kusto
// URL click action breakdown — piechart with title
UrlClickEvents
// | where Timestamp > ago(7d)
| summarize Count = count() by ActionType
| render piechart with (
    title='URL click outcomes'
)
```

[back to top](#kql-intermediate-series)

---

<a id="datetime_diff" name="datetime_diff"></a>
## datetime_diff()

- Calculates the difference between two datetime values.
- Returns difference in specified units (second, minute, hour, day, etc.).
- Useful for measuring time between events.

> Row-level sequencing (comparing each row to the previous one) requires `serialize` and `prev()` — covered in the advanced lesson.

**How `datetime_diff()` works**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
datetime_diff('unit', datetime1, datetime2)

Units: second, minute, hour, day, week, month, quarter, year

Example:
datetime_diff('minute', ClickTime, EmailTime)
    → Minutes between email receipt and URL click

┌────────────────────┬────────────────────┬─────────────────┐
│ EmailTime          │ ClickTime          │ MinutesToClick  │
├────────────────────┼────────────────────┼─────────────────┤
│ 2024-01-15 09:00   │ 2024-01-15 09:05   │ 5               │
│ 2024-01-15 10:00   │ 2024-01-15 11:30   │ 90              │
└────────────────────┴────────────────────┴─────────────────┘
</pre>

**Examples**

```kusto
// Calculate time from email to URL click
EmailEvents                                          // Query email events
// | where Timestamp > ago(7d)                          // Rolling 7-day window
| join kind=inner (                                  // Join with URL clicks
    UrlClickEvents
    // | where Timestamp > ago(7d)                      // Same rolling window
    | where ActionType == "ClickBlocked"
    | project                                        // Select click fields
        NetworkMessageId,
        ClickTime = Timestamp,
        AccountUpn,
        IsClickedThrough
    )
    on NetworkMessageId                              // Join on message ID
| extend                                             // Calculate time difference
    SecondsToClick = datetime_diff('second', ClickTime, Timestamp)
| project                                            // Select output columns
    EmailTime = Timestamp,
    ClickTime,
    SecondsToClick,
    Subject,
    AccountUpn
| sort by SecondsToClick asc                         // Fastest clicks first
// | take 20                                            // Top 20
```

```kusto
// How old (in hours) are current open alerts?
AlertInfo
| where Timestamp > ago(7d)
| extend AgeHours = datetime_diff('hour', now(), Timestamp)
| project Timestamp, AgeHours, Title, Severity, Category
| sort by AgeHours desc
```

```kusto
// Time between first and last sign-in failure per user (hours)
EntraIdSignInEvents
| where Timestamp > ago(30d)
| where ErrorCode != 0
| summarize
    FirstFailure = min(Timestamp),
    LastFailure  = max(Timestamp)
    by AccountUpn
| extend FailureSpanHours = datetime_diff('hour', LastFailure, FirstFailure)
| sort by FailureSpanHours desc
```

```kusto
// Time span between first and last URL click per user
UrlClickEvents
| where Timestamp > ago(30d)
| summarize
    FirstClick = min(Timestamp),
    LastClick  = max(Timestamp)
    by AccountUpn
| extend SpanHours = datetime_diff('hour', LastClick, FirstClick)
| where SpanHours > 0
| sort by SpanHours desc
```

**Two-pass baseline exclusion**

A common let pattern: build a known set from a historical window, then exclude it from the current window. Useful for detecting first-time or anomalous behavior.

```kusto
// Two-pass baseline exclusion — detect senders with a new bulk spike
// Pass 1: build the set of known high-volume senders over the last 30 days (excluding today)
let knownBulkSenders =
    EmailEvents
    | where Timestamp between (ago(30d) .. ago(1d))
    | where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
    | summarize RecipientCount = dcount(RecipientEmailAddress)
        by SenderFromAddress, bin(Timestamp, 10m)
    | where RecipientCount > 500
    | distinct SenderFromAddress;
// Pass 2: find today's bulk senders not seen before
EmailEvents
| where Timestamp > ago(1d)
| where EmailDirection == "Inbound"
| where SenderFromAddress !in (knownBulkSenders)
| summarize RecipientCount = dcount(RecipientEmailAddress)
    by SenderFromAddress, bin(Timestamp, 10m)
| where RecipientCount > 500
| sort by RecipientCount desc
```

[back to top](#kql-intermediate-series)

---

<a id="let" name="let"></a>
## let

- Use `let` to define variables or reusable expressions.
- Variables can hold values, arrays, or table queries.

**How `let` works**
```kusto
let _timeFrame = 7d;                     // Value
let _badDomains = dynamic(["x","y"]);    // Array
let _suspiciousEmails = EmailEvents      // Table query
| where Subject has "invoice";
```
<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
                  │
                  ▼
</pre>
```kusto
// Use variables in your query
suspiciousEmails
| where Timestamp > ago(timeframe)
| where SenderFromDomain in (badDomains)
```
**Examples**

```kusto
let timeframe = 3h;                     // Define a reusable time window (last 7 days)
EmailEvents                             // Query the EmailEvents table
| where Timestamp > ago(timeframe)      // Filter events using the timeframe variable
| summarize                             // Aggregate by sender domain
    count()                             // Count email events per sender domain
    by SenderFromDomain                 // One row per sender domain
```

```kusto
// create array
let suspiciousDomains = dynamic(["evil.com", "phish.net","groupon.com"]);         // Define a list of suspicious domains
EmailUrlInfo                                                        // Query URL metadata from email events
| where UrlDomain in (suspiciousDomains)                            // Return only URLs matching the suspicious domain list
```

```kusto
// create subqueries (named datasets)
let failedLogons =                              // Define a reusable subquery for failed sign-ins
    IdentityLogonEvents                         // Query identity logon events
    | where ActionType == "LogonFailed";        // Filter to failed logon attempts only
failedLogons                                    // Reference the failedLogons subquery
| summarize                                     // Aggregate failed logons by application
    Count = count() by Application              // Count failed sign-in events per application
```

**datatable — define an inline reference table**

`datatable(Column:type, ...) [value1, value2, ...]` creates an in-memory table from literal values.  
Use it with `let` to define static reference data — severity maps, error code descriptions, IOC lists — without needing an external file or a persistent table.

The example below creates a small user and order dataset to demonstrate join and lookup patterns.

```kusto
// create tables
let Users = datatable(UserId:int, UserName:string)
[
    1, "Alice",
    2, "Bob",
    3, "Carol",
    4, "Dan",
    5, "Eve",
    6, "Frank"
];
let Orders = datatable(UserId:int, OrderId:int, Amount:int)
[
    1, 101, 250,
    2, 102, 175,
    2, 103, 320,
    3, 104, 150,
    7, 105, 400
];
Users
// | where UserName contains "Dan"
// Orders
```

```kusto
// let — reusable timeframe and severity for alert hunting
let timeframe = 7d;
let minSeverity = "High";
AlertInfo
| where Timestamp > ago(timeframe)
| where Severity == minSeverity
| project Timestamp, Title, Severity, Category, ServiceSource
| sort by Timestamp desc
```

```kusto
// let — define risky Entra error codes as a reusable array
let riskyErrorCodes = dynamic([50126, 50053, 50057, 50074]);
EntraIdSignInEvents
| where Timestamp > ago(7d)
| where ErrorCode in (riskyErrorCodes)
| project Timestamp, AccountUpn, Application, IPAddress, Country, ErrorCode
| sort by Timestamp desc
```

```kusto
// let — subquery: users who clicked blocked URLs, then look up their sign-ins
let usersWithBlockedClicks =
    UrlClickEvents
    | where Timestamp > ago(7d)
    | where ActionType == "ClickBlocked"
    | distinct AccountUpn;
EntraIdSignInEvents
| where Timestamp > ago(7d)
| where AccountUpn in (usersWithBlockedClicks)
| project Timestamp, AccountUpn, Application, Country, ErrorCode
| sort by Timestamp desc
```

[back to top](#kql-intermediate-series)

---

<a id="type-conversion" name="type-conversion"></a>
## Type conversion functions

KQL is a typed language — type mismatches produce silent failures or null results rather than errors. Explicit casting is needed any time a value's type doesn't match what the next operation expects.

Common situations:
- Dynamic column access — values from `parse_json()` or `AdditionalFields` have no fixed type
- Array element access — `split()` results and `[]` indexing return `dynamic` values
- Arithmetic precision — `tolong()` before division prevents integer truncation
- Join key alignment — when the same field has different types across tables

| Function | Converts to |
|---|---|
| `tostring()` | String |
| `toint()` | Integer |
| `tolong()` | Large integer — use for counts, file sizes, and numeric timestamps |
| `todouble()` | Decimal number |
| `tobool()` | Boolean |
| `todatetime()` | Datetime |
| `totimespan()` | Timespan |

All functions return `null` (not an error) when the value cannot be converted.

**Examples**

```kusto
CloudAppEvents
| where TimeGenerated >= ago(2h)
| where Application in (
    "Microsoft SharePoint Online",
    "Microsoft OneDrive for Business"
    )
| where ActionType in~ (
    "CompanyLinkCreated",
    "CompanyLinkUpdated",
    "SharingLinkCreated",
    "SharingLinkUpdated",
    "AnonymousLinkCreated",
    "AnonymousLinkUpdated",
    "SecureLinkCreated",
    "SecureLinkUpdated",
    "SharingSet",
    "AddedToSharingLink",
    "AddedToSecureLink"
    )
| extend Raw = parse_json(RawEventData)
| extend
    ShareObjectId              = tostring(Raw.ObjectId),
    ShareUserId                = tostring(Raw.UserId),
    SharePermission            = tostring(Raw.Permission),
    ShareSharingLinkScope      = tostring(Raw.SharingLinkScope),
    ShareEV                    = tostring(Raw.EventData),
    ShareTargetUserOrGroupName = tostring(Raw.TargetUserOrGroupName),
    ShareTargetUserOrGroupType = tostring(Raw.TargetUserOrGroupType),
    ShareItemType              = tostring(Raw.ItemType)
| where isnotempty(ShareObjectId)
| project
    ShareTime                  = TimeGenerated,
    ShareAction                = ActionType,
    ShareObjectId,
    ShareItemType,
    ShareUserId,
    SharePermission,
    ShareSharingLinkScope,
    ShareEV,
    ShareTargetUserOrGroupName,
    ShareTargetUserOrGroupType,
    RawEventData,
    Application
```

```kusto
let dlp_files = toscalar(
    CloudAppEvents
    | where TimeGenerated >= ago(90d)
    | where Application in (
        "Microsoft SharePoint Online",
        "Microsoft OneDrive for Business"
        )
    | where ActionType =~ "DLPRuleMatch"
    | where isnotempty(ObjectName)
    | extend ObjectName = url_decode(ObjectName)
    | summarize make_set(ObjectName)
    );
CloudAppEvents
| where TimeGenerated >= ago(2h)
| where Application in (
    "Microsoft SharePoint Online",
    "Microsoft OneDrive for Business"
    )
| where ActionType in~ (
    "CompanyLinkCreated", 
    "CompanyLinkUpdated",
    "SharingLinkCreated",
    "SharingLinkUpdated",
    "AnonymousLinkCreated",
    "AnonymousLinkUpdated",
    "SecureLinkCreated",
    "SecureLinkUpdated",
    "SharingSet",
    "AddedToSharingLink",
    "AddedToSecureLink"
    )
| extend Raw = parse_json(RawEventData)
| extend ShareObjectId = tostring(Raw.ObjectId)
| where isnotempty(ShareObjectId)
| where ShareObjectId in (dlp_files)
| extend
    ShareUserId                = tostring(Raw.UserId),
    SharePermission            = tostring(Raw.Permission),
    ShareSharingLinkScope      = tostring(Raw.SharingLinkScope),
    ShareEV                    = tostring(Raw.EventData),
    ShareTargetUserOrGroupName = tostring(Raw.TargetUserOrGroupName),
    ShareTargetUserOrGroupType = tostring(Raw.TargetUserOrGroupType),
    ShareItemType              = tostring(Raw.ItemType)
| project
    TimeGenerated,
    ShareTime                  = TimeGenerated,
    ShareAction                = ActionType,
    ShareObjectId,
    ShareItemType,
    ShareUserId,
    SharePermission,
    ShareSharingLinkScope,
    ShareEV,
    ShareTargetUserOrGroupName,
    ShareTargetUserOrGroupType,
    RawEventData,
    Application
```

```kusto
CloudAppEvents
| where TimeGenerated >= ago(90d)
| where Application in (
    "Microsoft SharePoint Online",
    "Microsoft OneDrive for Business"
    )
| where ActionType =~ "DLPRuleMatch"
| where isnotempty(ObjectName)
| extend ObjectName = url_decode(ObjectName)
| extend Raw = parse_json(RawEventData)
| extend
    RawIncidentId       = tostring(Raw.IncidentId),
    RawUserId           = tostring(Raw.UserId),
    RawCreationTime     = todatetime(Raw.SharePointMetaData.ItemCreationTime),
    RawLastModifiedTime = todatetime(Raw.SharePointMetaData.ItemLastModifiedTime)
| mv-expand Policy = Raw.PolicyDetails
| extend
    RawPolicyId   = tostring(Policy.PolicyId),
    RawPolicyName = tostring(Policy.PolicyName)
| mv-expand Rule = Policy.Rules
| extend
    RawRuleId   = tostring(Rule.RuleId),
    RawRuleName = tostring(Rule.RuleName)
| project
    DLPTime         = TimeGenerated,
    DLPAction       = ActionType,
    ObjectName,
    DLPUserId       = RawUserId,
    DLPIncidentId   = RawIncidentId,
    DLPPolicyId     = RawPolicyId,
    DLPPolicyName   = RawPolicyName,
    DLPRuleId       = RawRuleId,
    DLPRuleName     = RawRuleName,
    RawEventData,
    Application
```

[back to top](#kql-intermediate-series)

---

<a id="pack_array-bag_pack" name="pack_array-bag_pack"></a>
## pack_array() / bag_pack()

- `pack_array()` combines columns into an **ordered array** — fields referenced by index.
- `bag_pack()` creates a **named JSON object** — fields referenced by key name.

**pack_array() vs bag_pack()**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
pack_array(Sender, Recipient, Subject)
    → ["alice@contoso.com", "bob@fabrikam.com", "Invoice"]

bag_pack("Sender", Sender, "Recipient", Recipient, "Subject", Subject)
    → {
         "Sender": "alice@contoso.com",
         "Recipient": "bob@fabrikam.com",
         "Subject": "Invoice"
       }
</pre>

**Examples**

```kusto
EmailEvents
| where Timestamp >= ago(1d)
| project SenderFromAddress, RecipientEmailAddress, Subject
```

```kusto
EmailEvents                             // Query the EmailEvents table
| where Timestamp >= ago(1d)            // Limit to email events from the last 1 day
| project                               // Shape the output and build a compact context array
    NetworkMessageId,
    Context = pack_array(               // Bundle key email context into a single array
        SenderFromAddress,              //   [0] Sender email address
        RecipientEmailAddress,          //   [1] Recipient email address
        Subject                         //   [2] Email subject
    )
| join kind=inner (                     // Join with attachment metadata for the same messages
    EmailAttachmentInfo                 // Query email attachment information
    | project                           // Select only needed attachment fields
        NetworkMessageId,
        FileName,
        FileSize
) on NetworkMessageId                   // Join on the shared message identifier

```

```kusto
// Create a JSON object with email details
EmailEvents                                          // Query the EmailEvents table
| take 5                                             // Limit to 5 rows for demo
| extend                                             // Add a new column with packed JSON
    EmailSummary = bag_pack(                             // Create JSON object with named keys
        "Sender", SenderFromAddress,                 // Key-value pair for sender
        "Recipient", RecipientEmailAddress,          // Key-value pair for recipient
        "Subject", Subject                           // Key-value pair for subject
    )
| project Timestamp, EmailSummary                    // Display timestamp and packed summary
```

[back to top](#kql-intermediate-series)

---

<a id="join" name="join"></a>
## join

- `join` combines two tables based on matching keys.
- Most common join types: `inner`, `leftouter`, `leftsemi`, `leftanti`.

**Key takeaways**
- **Join adds columns** from the right table to matching left rows — unlike `union`, which appends entire rows from a second table
- Rows match where the **join key values are equal**
- Columns from **both tables** can appear in the result
- One-to-many matches cause **row duplication** — a left row is repeated for each match on the right
- Join kind controls **which rows survive**

![alt text](https://learn.microsoft.com/en-us/kusto/query/media/joinoperator/join-kinds.png?view=microsoft-fabric)

**Examples**

### inner join
Returns only rows where the key exists in **both** tables.

**Before**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
EmailEvents - Left Table                                          EmailAttachmentInfo - Right Table
┌──────────────────┬───────────┬────────────────┬────────┐        ┌──────────────────┬──────────────┬──────────┬──────────┬────────┬───────────┐
│ NetworkMessageId │ Timestamp │ Subject        │ Sender │        │ NetworkMessageId │ FileName     │ FileType │ FileSize │ SHA256 │ Recipient │
├──────────────────┼───────────┼────────────────┼────────┤        ├──────────────────┼──────────────┼──────────┼──────────┼────────┼───────────┤
│ A1               │ 10:01     │ Invoice        │ a@z    │        │ A1               │ invoice.pdf  │ PDF      │ 400KB    │ aaa111 │ z@a       │
│ B2               │ 10:02     │ Payroll        │ b@y    │        │ A2               │ readme.txt   │ TXT      │ 12KB     │ bbb222 │ y@b       │
│ C3               │ 10:03     │ Team Update    │ c@x    │        │ D6               │ agenda.docx  │ DOCX     │ 89KB     │ ccc333 │ x@c       │
│ E5               │ 10:04     │ Quarterly Plan │ e@w    │        └──────────────────┴──────────────┴──────────┴──────────┴────────┴───────────┘
│ D6               │ 10:07     │ Annual Report  │ d@v    │
└──────────────────┴───────────┴────────────────┴────────┘
</pre>

**After – inner join (on `NetworkMessageId`)**
> Keeps **only rows that exist in both tables**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
┌──────────────────┬───────────┬───────────────┬────────┬──────────────┬──────────┬──────────┬────────┬───────────┐
│ NetworkMessageId │ Timestamp │ Subject       │ Sender │ FileName     │ FileType │ FileSize │ SHA256 │ Recipient │
├──────────────────┼───────────┼───────────────┼────────┼──────────────┼──────────┼──────────┼────────┼───────────┤
│ A1               │ 10:01     │ Invoice       │ a@z    │ invoice.pdf  │ PDF      │ 400KB    │ aaa111 │ z@a       │
│ D6               │ 10:07     │ Annual Report │ d@v    │ agenda.docx  │ DOCX     │ 89KB     │ ccc333 │ x@c       │
└──────────────────┴───────────┴───────────────┴────────┴──────────────┴──────────┴──────────┴────────┴───────────┘
</pre>
---
<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
Users                    Orders                     inner join Result
┌────────┬─────────┐     ┌────────┬─────────┐       ┌────────┬─────────┬─────────┬────────┐
│ UserId │ UserName│     │ UserId │ OrderId │       │ UserId │ UserName│ OrderId │ Amount │
├────────┼─────────┤     ├────────┼─────────┤       ├────────┼─────────┼─────────┼────────┤
│ 1      │ Alice   │  →  │ 1      │ 101     │   →   │ 1      │ Alice   │ 101     │ 250    │
│ 2      │ Bob     │  →  │ 2      │ 102     │   →   │ 2      │ Bob     │ 102     │ 175    │
│ 2      │ Bob     │  →  │ 2      │ 103     │   →   │ 2      │ Bob     │ 103     │ 320    │
│ 3      │ Carol   │  →  │ 3      │ 104     │   →   │ 3      │ Carol   │ 104     │ 150    │
│ 4      │ Dan     │     └────────┴─────────┘       └────────┴─────────┴─────────┴────────┘
│ 5      │ Eve     │     
│ 6      │ Frank   │     Users 4,5,6 have no orders → excluded
└────────┴─────────┘     Order 105 (UserId 7) has no user → excluded
</pre>

```kusto
// inner join - only matching rows from both tables
let Users = datatable(UserId:int, UserName:string)          // Define left table: Users
[
    1, "Alice",
    2, "Bob",
    3, "Carol",
    4, "Dan",
    5, "Eve",
    6, "Frank"
];
let Orders = datatable(UserId:int, OrderId:int, Amount:int)  // Define right table: Orders
[
    1, 101, 250,
    2, 102, 175,
    2, 103, 320,                                            // Bob has 2 orders
    3, 104, 150,
    7, 105, 400                                             // UserId 7 not in Users
];
Users                                                       // Start with Users table
| join kind=inner Orders on UserId                          // Join only where UserId exists in both
| project UserId, UserName, OrderId, Amount                 // Select final columns
```

### leftouter join
Returns **all rows from the left** table, with nulls where no match exists on the right.

**Before**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
EmailEvents - Left Table                                          EmailAttachmentInfo - Right Table
┌──────────────────┬───────────┬────────────────┬────────┐        ┌──────────────────┬──────────────┬──────────┬──────────┬────────┬───────────┐
│ NetworkMessageId │ Timestamp │ Subject        │ Sender │        │ NetworkMessageId │ FileName     │ FileType │ FileSize │ SHA256 │ Recipient │
├──────────────────┼───────────┼────────────────┼────────┤        ├──────────────────┼──────────────┼──────────┼──────────┼────────┼───────────┤
│ A1               │ 10:01     │ Invoice        │ a@z    │        │ A1               │ invoice.pdf  │ PDF      │ 400KB    │ aaa111 │ z@a       │
│ B2               │ 10:02     │ Payroll        │ b@y    │        │ A2               │ readme.txt   │ TXT      │ 12KB     │ bbb222 │ y@b       │
│ C3               │ 10:03     │ Team Update    │ c@x    │        │ D6               │ agenda.docx  │ DOCX     │ 89KB     │ ccc333 │ x@c       │
│ E5               │ 10:04     │ Quarterly Plan │ e@w    │        └──────────────────┴──────────────┴──────────┴──────────┴────────┴───────────┘
│ D6               │ 10:07     │ Annual Report  │ d@v    │
└──────────────────┴───────────┴────────────────┴────────┘
</pre>

**After – leftouter join (on `NetworkMessageId`)**
> Keeps **all left rows**, nulls if no match on right

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
┌──────────────────┬───────────┬────────────────┬────────┬──────────────┬──────────┬──────────┬────────┬───────────┐
│ NetworkMessageId │ Timestamp │ Subject        │ Sender │ FileName     │ FileType │ FileSize │ SHA256 │ Recipient │
├──────────────────┼───────────┼────────────────┼────────┼──────────────┼──────────┼──────────┼────────┼───────────┤
│ A1               │ 10:01     │ Invoice        │ a@z    │ invoice.pdf  │ PDF      │ 400KB    │ aaa111 │ z@a       │
│ B2               │ 10:02     │ Payroll        │ b@y    │ null         │ null     │ null     │ null   │ null      │
│ C3               │ 10:03     │ Team Update    │ c@x    │ null         │ null     │ null     │ null   │ null      │
│ E5               │ 10:04     │ Quarterly Plan │ e@w    │ null         │ null     │ null     │ null   │ null      │
│ D6               │ 10:07     │ Annual Report  │ d@v    │ agenda.docx  │ DOCX     │ 89KB     │ ccc333 │ x@c       │
└──────────────────┴───────────┴────────────────┴────────┴──────────────┴──────────┴──────────┴────────┴───────────┘
</pre>
---
<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
Users                    Orders                     leftouter join Result
┌────────┬─────────┐     ┌────────┬─────────┐       ┌────────┬─────────┬─────────┬────────┐
│ UserId │ UserName│     │ UserId │ OrderId │       │ UserId │ UserName│ OrderId │ Amount │
├────────┼─────────┤     ├────────┼─────────┤       ├────────┼─────────┼─────────┼────────┤
│ 1      │ Alice   │  →  │ 1      │ 101     │   →   │ 1      │ Alice   │ 101     │ 250    │
│ 2      │ Bob     │  →  │ 2      │ 102     │   →   │ 2      │ Bob     │ 102     │ 175    │
│ 2      │ Bob     │  →  │ 2      │ 103     │   →   │ 2      │ Bob     │ 103     │ 320    │
│ 3      │ Carol   │  →  │ 3      │ 104     │   →   │ 3      │ Carol   │ 104     │ 150    │
│ 4      │ Dan     │  →                         →   │ 4      │ Dan     │ null    │ null   │
│ 5      │ Eve     │  →                         →   │ 5      │ Eve     │ null    │ null   │
│ 6      │ Frank   │  →                         →   │ 6      │ Frank   │ null    │ null   │
└────────┴─────────┘     └────────┴─────────┘       └────────┴─────────┴─────────┴────────┘
                         Order 105 (UserId 7) still excluded (no left match)
</pre>

```kusto
// leftouter join - all left rows, nulls if no right match
let Users = datatable(UserId:int, UserName:string)              // Define left table: Users
[
    1, "Alice",
    2, "Bob",
    3, "Carol",
    4, "Dan",
    5, "Eve",
    6, "Frank"
];
let Orders = datatable(UserId:int, OrderId:int, Amount:int)     // Define right table: Orders
[
    1, 101, 250,
    2, 102, 175,
    2, 103, 320,
    3, 104, 150,
    7, 105, 400
];
Users                                                           // Start with Users table
| join kind=leftouter Orders on UserId                          // Keep all users, nulls if no orders
| project UserId, UserName, OrderId, Amount                     // Select final columns
```

### leftsemi join
Returns **left rows that have a match** in the right table, but **no right columns** are added.
Use this when you only want to filter the left table.

**Before**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
EmailEvents - Left Table                                          EmailAttachmentInfo - Right Table
┌──────────────────┬───────────┬────────────────┬────────┐        ┌──────────────────┬──────────────┬──────────┬──────────┬────────┬───────────┐
│ NetworkMessageId │ Timestamp │ Subject        │ Sender │        │ NetworkMessageId │ FileName     │ FileType │ FileSize │ SHA256 │ Recipient │
├──────────────────┼───────────┼────────────────┼────────┤        ├──────────────────┼──────────────┼──────────┼──────────┼────────┼───────────┤
│ A1               │ 10:01     │ Invoice        │ a@z    │        │ A1               │ invoice.pdf  │ PDF      │ 400KB    │ aaa111 │ z@a       │
│ B2               │ 10:02     │ Payroll        │ b@y    │        │ A2               │ readme.txt   │ TXT      │ 12KB     │ bbb222 │ y@b       │
│ C3               │ 10:03     │ Team Update    │ c@x    │        │ D6               │ agenda.docx  │ DOCX     │ 89KB     │ ccc333 │ x@c       │
│ E5               │ 10:04     │ Quarterly Plan │ e@w    │        └──────────────────┴──────────────┴──────────┴──────────┴────────┴───────────┘
│ D6               │ 10:07     │ Annual Report  │ d@v    │
└──────────────────┴───────────┴────────────────┴────────┘
</pre>

**After – leftsemi join (on `NetworkMessageId`)**
> Keeps **left rows that have a match**, but **no right columns added**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
┌──────────────────┬───────────┬───────────────┬────────┐
│ NetworkMessageId │ Timestamp │ Subject       │ Sender │
├──────────────────┼───────────┼───────────────┼────────┤
│ A1               │ 10:01     │ Invoice       │ a@z    │
│ D6               │ 10:07     │ Annual Report │ d@v    │
└──────────────────┴───────────┴───────────────┴────────┘
</pre>
---
<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
Users                    Orders                     leftsemi join Result
┌────────┬─────────┐     ┌────────┬─────────┐       ┌────────┬─────────┐
│ UserId │ UserName│     │ UserId │ OrderId │       │ UserId │ UserName│  ← No Order columns
├────────┼─────────┤     ├────────┼─────────┤       ├────────┼─────────┤
│ 1      │ Alice   │  →  │ 1      │ 101     │   →   │ 1      │ Alice   │
│ 2      │ Bob     │  →  │ 2      │ 102,103 │   →   │ 2      │ Bob     │  ← Only 1 row (no dups)
│ 3      │ Carol   │  →  │ 3      │ 104     │   →   │ 3      │ Carol   │
│ 4      │ Dan     │     └────────┴─────────┘       └────────┴─────────┘
│ 5      │ Eve     │     
│ 6      │ Frank   │     Users 4,5,6 have no orders → excluded
└────────┴─────────┘     Bob appears once (not duplicated by multiple orders)
</pre>

```kusto
// leftsemi join - filter left table, no right columns added
let Users = datatable(UserId:int, UserName:string)              // Define left table: Users
[
    1, "Alice",
    2, "Bob",
    3, "Carol",
    4, "Dan",
    5, "Eve",
    6, "Frank"
];
let Orders = datatable(UserId:int, OrderId:int, Amount:int)     // Define right table: Orders
[
    1, 101, 250,
    2, 102, 175,
    2, 103, 320,                                                // Bob's 2 orders won't duplicate him
    3, 104, 150,
    7, 105, 400
];
Users                                                           // Start with Users table
| join kind=leftsemi Orders on UserId                           // Keep only users who have orders
// Result: Only left columns, no duplicates from multiple matches
```

### leftanti join
Returns **left rows that have no match** in the right table. Useful for finding rows with no match.


**Before**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
EmailEvents - Left Table                                          EmailAttachmentInfo - Right Table
┌──────────────────┬───────────┬────────────────┬────────┐        ┌──────────────────┬──────────────┬──────────┬──────────┬────────┬───────────┐
│ NetworkMessageId │ Timestamp │ Subject        │ Sender │        │ NetworkMessageId │ FileName     │ FileType │ FileSize │ SHA256 │ Recipient │
├──────────────────┼───────────┼────────────────┼────────┤        ├──────────────────┼──────────────┼──────────┼──────────┼────────┼───────────┤
│ A1               │ 10:01     │ Invoice        │ a@z    │        │ A1               │ invoice.pdf  │ PDF      │ 400KB    │ aaa111 │ z@a       │
│ B2               │ 10:02     │ Payroll        │ b@y    │        │ A2               │ readme.txt   │ TXT      │ 12KB     │ bbb222 │ y@b       │
│ C3               │ 10:03     │ Team Update    │ c@x    │        │ D6               │ agenda.docx  │ DOCX     │ 89KB     │ ccc333 │ x@c       │
│ E5               │ 10:04     │ Quarterly Plan │ e@w    │        └──────────────────┴──────────────┴──────────┴──────────┴────────┴───────────┘
│ D6               │ 10:07     │ Annual Report  │ d@v    │
└──────────────────┴───────────┴────────────────┴────────┘
</pre>

**After – leftanti join (on `NetworkMessageId`)**
> Keeps **left rows that have no match** in right table

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
┌──────────────────┬───────────┬────────────────┬────────┐
│ NetworkMessageId │ Timestamp │ Subject        │ Sender │
├──────────────────┼───────────┼────────────────┼────────┤
│ B2               │ 10:02     │ Payroll        │ b@y    │
│ C3               │ 10:03     │ Team Update    │ c@x    │
│ E5               │ 10:04     │ Quarterly Plan │ e@w    │
└──────────────────┴───────────┴────────────────┴────────┘
</pre>
---
<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
Users                    Orders                     leftanti join Result
┌────────┬─────────┐     ┌────────┬─────────┐       ┌────────┬─────────┐
│ UserId │ UserName│     │ UserId │ OrderId │       │ UserId │ UserName│
├────────┼─────────┤     ├────────┼─────────┤       ├────────┼─────────┤
│ 1      │ Alice   │  →  │ 1      │ 101     │       │ 4      │ Dan     │  ← No orders
│ 2      │ Bob     │  →  │ 2      │ 102     │       │ 5      │ Eve     │  ← No orders
│ 3      │ Carol   │  →  │ 3      │ 104     │       │ 6      │ Frank   │  ← No orders
│ 4      │ Dan     │  →                         →   └────────┴─────────┘
│ 5      │ Eve     │  →                         →
│ 6      │ Frank   │  →                         →    Only users WITHOUT orders
└────────┴─────────┘     └────────┴─────────┘ 
</pre>

```kusto
// leftanti join — find threats that arrived but were never remediated
// Keep all rows from EmailEvents that have NO matching row in EmailPostDeliveryEvents
// The composite key (NetworkMessageId + RecipientEmailAddress) ensures per-recipient accuracy:
// the same message can be remediated for one recipient but not another
EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes in ("Phish", "Malware")
    and EmailAction !in ("Replace attachment", "Send to quarantine")
| join kind=leftanti EmailPostDeliveryEvents
    on NetworkMessageId, RecipientEmailAddress
| project Timestamp, SenderFromAddress, RecipientEmailAddress,
    Subject, ThreatTypes, DeliveryLocation
```

---

### Duplicate join keys in security telemetry

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
EmailEvents (7 rows)                                      EmailAttachmentInfo (2 rows)
┌───────────────────┬────────────────────────────┐        ┌───────────────────┬───────────────┐
│ NetworkMessageId  │ RecipientEmailAddress      │        │ NetworkMessageId  │ FileName      │
├───────────────────┼────────────────────────────┤        ├───────────────────┼───────────────┤
│ ABC123            │ user1@contoso.com          │        │ ABC123            │ invoice.pdf   │
│ ABC123            │ user2@contoso.com          │        │ ABC123            │ invoice.pdf   │
│ ABC123            │ user3@contoso.com          │        └───────────────────┴───────────────┘
│ ABC123            │ user4@contoso.com          │
│ ABC123            │ user5@contoso.com          │
│ ABC123            │ user6@contoso.com          │
│ ABC123            │ user7@contoso.com          │
└───────────────────┴────────────────────────────┘

INNER JOIN ON NMID

Result (14 rows)
┌───────────────────────┬──────────────────────┬───────────────┐
│ NetworkMessageId      │ RecipientEmailAddress│ FileName      │
├───────────────────────┼──────────────────────┼───────────────┤
│ ABC123                │ user1                │ invoice.pdf   │
│ ABC123                │ user1                │ invoice.pdf   │  ← duplicate appearance
│ ABC123                │ user2                │ invoice.pdf   │
│ ABC123                │ user2                │ invoice.pdf   │  ← duplicate appearance
│ ABC123                │ user3                │ invoice.pdf   │
│ ABC123                │ user3                │ invoice.pdf   │  ← duplicate appearance
│ ABC123                │ user4                │ invoice.pdf   │
│ ABC123                │ user4                │ invoice.pdf   │  ← duplicate appearance
│ ABC123                │ user5                │ invoice.pdf   │
│ ABC123                │ user5                │ invoice.pdf   │  ← duplicate appearance
│ ...                   │ ...                  │ ...           │
└───────────────────────┴──────────────────────┴───────────────┘
</pre>

<br>

> If a join key is non-unique on both sides, the output row count is the product of the matches

```kusto
// Demonstrating row multiplication from non-unique join keys
let Emails = datatable(MessageId:string, Recipient:string)              // Left table: 4 recipients for same message
[
    "ABC123", "user1@contoso.com",
    "ABC123", "user2@contoso.com",
    "ABC123", "user3@contoso.com",
    "ABC123", "user4@contoso.com"
];
let Attachments = datatable(MessageId:string, FileName:string)          // Right table: 2 attachments for same message
[
    "ABC123", "invoice.pdf",
    "ABC123", "invoice.pdf"
];
Emails                                                                  // Start with 4 email rows
| join kind=inner Attachments on MessageId                              // Join to 2 attachment rows
| project MessageId, Recipient, FileName                                // Result: 4 × 2 = 8 rows
// Each recipient appears twice (once per attachment)
```

In Microsoft Defender Advanced Hunting tables, it is very common for the join key to appear multiple times.

A good example is: `NetworkMessageId`

In tables such as:

 - EmailEvents
 - EmailAttachmentInfo
 - EmailUrlInfo

This key does not represent a single row. Instead, it represents a message entity that can fan out into multiple rows.

Sample scenarios:

| Scenario | Resulting rows |
|----------|----------------|
| 5 recipients | 5 rows |
| 5 attachments | 5 rows |
| 5 recipients × 5 attachments | 25 rows |

Sample table:

| NetworkMessageId | Recipient | FileName |
| ---------------- | --------- | -------- |
| A                | user1     | file1    |
| A                | user1     | file2    |
| A                | user1     | file3    |
| A                | user2     | file1    |
| A                | user2     | file2    |
| ...              | ...       | ...      |

Deduping the join key e.g. `NetworkMessageId` would lead to losing:

 - attachment identity
 - recipient fanout
 - attachment counts
 - investigative context

**Dedupe methods**

```kusto
// return unique NMID
EmailAttachmentInfo
| distinct NetworkMessageId
```

#### Scenario 1

Preserve Message + Attachment relationship

```kusto
EmailAttachmentInfo
| distinct NetworkMessageId, FileName
```

#### Scenario 2

Preserve Message + Recipient relationship

```kusto
EmailAttachmentInfo
| distinct NetworkMessageId, RecipientEmailAddress
```

#### Scenario 3

Preserve all details (no dedupe)

```kusto
EmailAttachmentInfo
| project NetworkMessageId, FileName, RecipientEmailAddress
```

#### Scenario 4

Aggregation — one row per message

```kusto
EmailAttachmentInfo
| summarize
    Recipients = make_set(RecipientEmailAddress),
    Attachments = make_set(FileName)
by NetworkMessageId
```

#### Row explosion

For example: 5 recipients × 25 attachments per message = 125 result rows.

```kusto
EmailAttachmentInfo
| where NetworkMessageId == "3ef8bae6-ec9a-4963-ed75-08de7f6aa06d"
```

```kusto
EmailEvents
| where NetworkMessageId == "3ef8bae6-ec9a-4963-ed75-08de7f6aa06d"
```

```kusto
let _EE = EmailEvents
| where NetworkMessageId == "3ef8bae6-ec9a-4963-ed75-08de7f6aa06d";
_EE
| join kind=inner EmailAttachmentInfo on NetworkMessageId
```

#### Alternatives

Reshape first, one row per message on both sides?

```kusto
let _Emails =
    EmailEvents
    | where Timestamp > ago(1d)
    | summarize Recipients = make_set(RecipientEmailAddress)
        by NetworkMessageId;
let _Attachments =
    EmailAttachmentInfo
    | where Timestamp > ago(1d)
    | summarize
        Files = make_set(FileName),
        Hashes = make_set(SHA256),
        AttachmentCount = dcount(SHA256)
        by NetworkMessageId;
_Emails
| join kind=inner _Attachments on NetworkMessageId
```

---

### Different interpretations

#### Version 1: top 20 largest files

"Top 20 largest files by attachment size"

- Selects the 20 largest files directly from EmailAttachmentInfo.
- A single message with many large attachments can occupy all 20 slots.
- The subsequent join with EmailEvents multiplies rows by recipient count.

So the output is:

> Up to 20 attachment rows before the join — a message with many large files can dominate all slots, and recipient fanout from the EmailEvents join applies after.

```kusto
let Attachmentinfo =                                                // Define a subquery for large attachments
    EmailAttachmentInfo                                             // Query email attachment metadata
    | where Timestamp >= ago(21d)                                   // Limit to attachments from the last x days
    | extend                                                        // Add a calculated size in MB
        FileSizeMB = round(FileSize / 1024.0 / 1024.0, 2)           // Convert bytes to MB
    | project                                                       // Select only required attachment fields
        NetworkMessageId,
        FileName,
        FileSize,
        FileSizeMB
    | top 20 by FileSize desc;                                      // Keep only the 20 largest attachments
Attachmentinfo                                                      // Start with the top attachment set
| join kind=inner (                                                 // Join to corresponding email events
    EmailEvents                                                     // Query email event metadata
    | project                                                       // Select only fields needed for analysis
        Timestamp,
        ReportId,
        RecipientEmailAddress,
        NetworkMessageId,
        SenderFromAddress,
        SenderFromDomain,
        Subject,
        DeliveryLocation,
        LatestDeliveryLocation,
        LatestDeliveryAction
    )
    on NetworkMessageId                                             // Join on NMID
| project                                                           // Shape final output
    NetworkMessageId,
    Timestamp,
    ReportId,
    RecipientEmailAddress,
    SenderFromAddress,
    SenderFromDomain,
    Subject,
    DeliveryLocation,
    LatestDeliveryLocation,
    LatestDeliveryAction,
    FileName,
    FileSize,
    FileSizeMB
| sort by FileSize desc                                             // Sort results by attachment size
```

#### Version 2: top 20 messages by largest single attachment

”Top 20 messages by their largest attachment”

- First you compute MaxFileSize per NetworkMessageId.
- Then you keep the top 20 messages whose largest attachment is biggest.
- Then you join back to EmailAttachmentInfo, which brings in all attachments for those 20 messages.

So even though it says “top 20”, the output is really:

> All attachment rows for the 20 messages that have the biggest single attachment.

```kusto
let Attachmentinfo =                                                // Define a subquery for max attachment size per message
    EmailAttachmentInfo                                             // Query email attachment metadata
    | where Timestamp >= ago(21d)                                   // Limit to attachments from the last x days
    | summarize                                                     // Aggregate per message
        MaxFileSize = max(FileSize)                                 // Find the largest attachment per message
        by NetworkMessageId                                         // One row per message
    | top 20 by MaxFileSize desc;                                   // Keep the 20 messages with largest attachments
EmailAttachmentInfo                                                 // Query attachment metadata again
| where Timestamp >= ago(21d)                                       // Apply the same time filter
| join kind=inner Attachmentinfo                                    // Join to messages with large attachments
    on NetworkMessageId                                             // Join key
| extend                                                            // Add calculated size in MB
    FileSizeMB = round(FileSize / 1024.0 / 1024.0, 2)               // Convert bytes to MB
| join kind=inner (                                                 // Join with latest email event per message
    EmailEvents                                                     // Query email events
    | where Timestamp >= ago(21d)                                   // Limit to the same time window
    | summarize                                                     // Select the most recent email event per message
        arg_max(
        Timestamp,                                                  // Choose the latest event
        ReportId,
        RecipientEmailAddress,
        SenderFromAddress,
        SenderFromDomain,
        Subject,
        DeliveryLocation,
        LatestDeliveryLocation,
        LatestDeliveryAction
        )
        by NetworkMessageId                                         // One row per message
    )
    on NetworkMessageId                                             // Join on message identifier
| sort by FileSize desc                                             // Sort by attachment size
| project-reorder                                                   // Reorder columns for analyst readability
    Timestamp,
    FileName,
    FileSizeMB,
    SenderFromAddress,
    RecipientEmailAddress,
    LatestDeliveryAction,
    LatestDeliveryLocation
```

#### Version 3: top 20 unique (message + filename) pairs

”Top 20 unique attachments by size”

- You first dedupe to one row per (NetworkMessageId, FileName).
- Then you join to one row of message metadata per message.
- Then you do top 20 by FileSize.

So the output is:

> Exactly 20 attachment rows (unless fewer exist), representing the largest 20 unique attachments.

```kusto
let Attachments =                                                   // Define unique attachment set
    EmailAttachmentInfo                                             // Query email attachment metadata
    | where Timestamp >= ago(1d)                                   // Limit to last x days
    | summarize                                                     // De-duplicate attachments
        FileSize = max(FileSize)                                    // Defensive max in case of duplicates
        by NetworkMessageId, FileName                               // One row per unique attachment
    | extend                                                        // Add derived columns
        FileSizeMB = round(FileSize / 1024.0 / 1024.0, 2);          // Convert bytes to MB
let MessageInfo =                                                   // Define per-message email metadata
    EmailEvents                                                     // Query email events
    | where Timestamp >= ago(1d)                                   // Match attachment time window
    | summarize                                                     // Select one representative event per message
        arg_max(
        Timestamp,                                                  // Choose the most recent event
        ReportId,
        RecipientEmailAddress,
        SenderFromAddress,
        SenderFromDomain,
        Subject,
        DeliveryLocation,
        LatestDeliveryLocation,
        LatestDeliveryAction
        )
        by NetworkMessageId;                                        // One row per message
Attachments                                                         // Start from unique attachments
| join kind=inner MessageInfo                                       // Join to message metadata
    on NetworkMessageId                                             // Join key
| top 20 by FileSize desc                                           // Select top 20 UNIQUE attachments by size
| project                                                           // Final projection
    NetworkMessageId,
    Timestamp,
    ReportId,
    RecipientEmailAddress,
    SenderFromAddress,
    SenderFromDomain,
    Subject,
    DeliveryLocation,
    LatestDeliveryLocation,
    LatestDeliveryAction,
    FileName,
    FileSize,
    FileSizeMB
```

**Which version to use?**

| | Version 1 | Version 2 | Version 3 |
|---|---|---|---|
| **"Top 20" means** | 20 largest files | 20 messages with the biggest single attachment | 20 largest unique (message + filename) pairs |
| **Multi-attachment messages** | Can dominate all 20 slots | Yes — ranked by message, not file | Yes — deduped by (message, filename) |
| **Duplicate attachment rows** | Susceptible | Partially mitigated | Yes — explicit dedupe |
| **Row count guarantee** | No — duplicates can reduce distinct results | Can exceed 20 | Yes — up to 20 |

Use Version 2 when you want to rank by message, not by individual file. Version 3 gives a clean, predictable result — 20 rows, no duplicates.

[back to top](#kql-intermediate-series)

---

<a id="union" name="union"></a>
## union

- Combines multiple tables with similar or compatible schema.
- Used to **append rows** from different sources into one result set.

**Before**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
EmailEvents                                                      EmailAttachmentInfo
┌──────────────────┬───────────┬────────────────┬────────┐       ┌──────────────────┬──────────────┬──────────┐
│ NetworkMessageId │ Timestamp │ Subject        │ Sender │       │ NetworkMessageId │ FileName     │ FileSize │
├──────────────────┼───────────┼────────────────┼────────┤       ├──────────────────┼──────────────┼──────────┤
│ A1               │ 10:01     │ Invoice        │ a@z    │       │ A1               │ invoice.pdf  │ 400KB    │
│ B2               │ 10:02     │ Payroll        │ b@y    │       │ D4               │ agenda.docx  │ 89KB     │
│ C3               │ 10:03     │ Team Update    │ c@x    │       └──────────────────┴──────────────┴──────────┘
└──────────────────┴───────────┴────────────────┴────────┘
</pre>

**After – union Result**
> Null cells from schema mismatch

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
┌──────────────────┬───────────┬────────────────┬────────┬──────────────┬──────────┐
│ NetworkMessageId │ Timestamp │ Subject        │ Sender │ FileName     │ FileSize │
├──────────────────┼───────────┼────────────────┼────────┼──────────────┼──────────┤
│ A1               │ 10:01     │ Invoice        │ a@z    │ null         │ null     │
│ B2               │ 10:02     │ Payroll        │ b@y    │ null         │ null     │
│ C3               │ 10:03     │ Team Update    │ c@x    │ null         │ null     │
│ A1               │ null      │ null           │ null   │ invoice.pdf  │ 400KB    │
│ D4               │ null      │ null           │ null   │ agenda.docx  │ 89KB     │
└──────────────────┴───────────┴────────────────┴────────┴──────────────┴──────────┘
</pre>

**Key takeaways**
- **Union adds rows**, not columns
- The result schema is the **union of all columns**
- Rows represent **different entity types** (emails *and* attachments)
- Columns that don't apply to a row are filled with **null**
- No join key or matching logic is used
- Best for **timelines**, **activity feeds**, and "show me everything" views

**Examples**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
Users                         Orders
┌────────┬──────────┐         ┌────────┬─────────┬────────┐
│ UserId │ UserName │         │ UserId │ OrderId │ Amount │
├────────┼──────────┤         ├────────┼─────────┼────────┤
│ 1      │ Alice    │         │ 1      │ 101     │ 250    │
│ 2      │ Bob      │         │ 2      │ 102     │ 175    │
│ 3      │ Carol    │         │ 2      │ 103     │ 320    │
│ 4      │ Dan      │         │ 3      │ 104     │ 150    │
│ 5      │ Eve      │         │ 7      │ 105     │ 400    │
│ 6      │ Frank    │         └────────┴─────────┴────────┘
└────────┴──────────┘
            │                            │
            └─────── union ──────────────┘
                       │
                       ▼

union Result (rows stacked, all columns included)
┌────────┬──────────┬─────────┬────────┐
│ UserId │ UserName │ OrderId │ Amount │
├────────┼──────────┼─────────┼────────┤
│ 1      │ Alice    │ null    │ null   │  ← from Users
│ 2      │ Bob      │ null    │ null   │  ← from Users
│ 3      │ Carol    │ null    │ null   │  ← from Users
│ 4      │ Dan      │ null    │ null   │  ← from Users
│ 5      │ Eve      │ null    │ null   │  ← from Users
│ 6      │ Frank    │ null    │ null   │  ← from Users
│ 1      │ null     │ 101     │ 250    │  ← from Orders
│ 2      │ null     │ 102     │ 175    │  ← from Orders
│ 2      │ null     │ 103     │ 320    │  ← from Orders
│ 3      │ null     │ 104     │ 150    │  ← from Orders
│ 7      │ null     │ 105     │ 400    │  ← from Orders
└────────┴──────────┴─────────┴────────┘

- UserId appears in both → single column (values preserved)
- UserName only in Users → null for Orders rows
- OrderId, Amount only in Orders → null for Users rows
- No matching or filtering → ALL rows from BOTH tables
</pre>

```kusto
let Users = datatable(UserId:int, UserName:string)              // Define left table: Users
[
    1, "Alice",
    2, "Bob",
    3, "Carol",
    4, "Dan",
    5, "Eve",
    6, "Frank"
];
let Orders = datatable(UserId:int, OrderId:int, Amount:int)     // Define right table: Orders
[
    1, 101, 250,
    2, 102, 175,
    2, 103, 320,
    3, 104, 150,
    7, 105, 400
];
union Users, Orders
```

```kusto
// Union two email-related tables and sample rows
union EmailEvents, EmailPostDeliveryEvents
| take 10
```

```kusto
// Union identity + cloud app events and count per day
union IdentityLogonEvents, CloudAppEvents               // Combine identity logons and cloud app activity into one dataset
| summarize                                             // Aggregate combined events into time buckets
    Total = count()                                     // Count total events per day across both tables
    by bin(Timestamp, 1d)                               // Group into 1-day time bins
```

```kusto
// Union URL tables and count total URLs/events
union EmailUrlInfo, UrlClickEvents                  // Combine URL metadata and URL click activity into one dataset
| summarize                                         // Aggregate across the entire combined dataset
    TotalUrls = count()                             // Count total rows across both tables
```

```kusto
// Union email and Teams post-delivery events — compare both channels
union
    (EmailPostDeliveryEvents
     | where Timestamp > ago(7d)
     | project Timestamp, ActionType, ThreatTypes, Channel = "Email"),
    (MessagePostDeliveryEvents
     | where Timestamp > ago(7d)
     | project Timestamp, ActionType, ThreatTypes, Channel = "Teams")
| summarize Count = count() by ActionType, Channel
| sort by Count desc
```

```kusto
// Union user and service principal sign-in failures — full identity picture
union
    (EntraIdSignInEvents
     | where Timestamp > ago(7d)
     | where ErrorCode != 0
     | project Timestamp, AccountUpn, Application, IPAddress, ErrorCode, Kind = "User"),
    (EntraIdSpnSignInEvents
     | where Timestamp > ago(7d)
     | where ErrorCode != 0
     | project Timestamp, AccountUpn = ServicePrincipalName, Application, IPAddress, ErrorCode, Kind = "ServicePrincipal")
| sort by Timestamp desc
| take 20
```

```kusto
// Union alerts and their evidence into one timeline
union
    (AlertInfo     | where Timestamp > ago(7d)
     | project Timestamp, Id = AlertId, Info = Title, Kind = "Alert"),
    (AlertEvidence | where Timestamp > ago(7d)
     | project Timestamp, Id = AlertId, Info = EntityType, Kind = "Evidence")
| sort by Timestamp desc
| take 20
```

[back to top](#kql-intermediate-series)

---

<a id="externaldata" name="externaldata"></a>
## externaldata

- Imports external CSV, JSON, or TSV data as an inline table at query time.
- The data source can be a public URL or an authenticated Azure Blob Storage URL (SAS token).
- The schema is declared inline: `externaldata(col1:type, col2:type) [url]`.
- Combine with `lookup` or `join` to enrich local telemetry with external threat intelligence or reference data.

> **Use case in security investigations:** load IOC feeds, hash blocklists, known-bad domains, or enrichment tables from external sources — all without importing data into a persistent table.

| Source type | URL format | Notes |
|---|---|---|
| Public HTTP | `[@"https://..."]` | No authentication, must allow anonymous reads |
| Azure Blob (SAS) | `[@"https://..."] h@"?<sas-token>"` | Use SAS token scoped to read on the container/blob |

**Examples**


```kusto
// Live threat intel — match email attachments against abuse.ch SHA256 blocklist
// externaldata() fetches the feed at query time; !startswith "#" strips comment lines
let MaliciousHashes = (
    externaldata(SHA256: string)
    [@"https://bazaar.abuse.ch/export/txt/sha256/recent/"]
    with (format="txt")
    | where SHA256 !startswith "#"
);
MaliciousHashes
| join kind=inner (
    EmailAttachmentInfo
    | where Timestamp > ago(1d)
) on SHA256
| project Timestamp, SenderFromAddress, RecipientEmailAddress,
    FileName, FileType, SHA256, ThreatTypes, DetectionMethods
```

```kusto
let imid =
    externaldata (Message_ID: string) [
        @"https://bwdemoblob.blob.core.windows.net/curated/EmailEvents_20260120_160736.csv"
        h@"?sp=r&st=2026-06-03T14:02:51Z&se=2026-06-03T22:17:51Z&spr=https&sv=2026-02-06&sr=b&sig=6uXz6dpzgbdnU3pT6DMQ3fWSCivggGEzD6cw7rxuMZs%3D"
    ]
    with (format='csv', ignorefirstrecord=true)
    | project Message_ID;
imid;
```

```kusto
let imid =
    externaldata (Message_ID:string) [
        @"https://bwdemoblob.blob.core.windows.net/curated/EmailEvents_20260120_160736.csv"
        h@"?sp=r&st=2026-06-03T14:02:51Z&se=2026-06-03T22:17:51Z&spr=https&sv=2026-02-06&sr=b&sig=6uXz6dpzgbdnU3pT6DMQ3fWSCivggGEzD6cw7rxuMZs%3D"
    ]
    with (format='csv', ignorefirstrecord=true)
    | project Message_ID;
EmailEvents
// | where Timestamp >= ago(30d)
| where RecipientEmailAddress == "lily.reed@contoso.com"
| where InternetMessageId in (imid)
```

```kusto
// Load hash blocklist from Azure Blob Storage (SAS-authenticated)
let BlockedHashes = (
    externaldata(SHA256:string)
    [
        @"https://<your-account>.blob.core.windows.net/<container>/hash-blocklist.txt"
        h@"?<your-sas-token>"
    ]
    with (format='txt')
    | where SHA256 !startswith "#"  // skip comment lines
    | project SHA256
);
EmailAttachmentInfo
| where Timestamp > ago(7d)
| where isnotempty(SHA256)
| lookup kind=inner BlockedHashes on SHA256
| project Timestamp, SenderFromAddress, FileName, SHA256
| take 20
```

[back to top](#kql-intermediate-series)

---

<a id="lookup" name="lookup"></a>
## lookup

- Adds fields from a smaller reference table to each row of a larger table.
- A cleaner alternative to `leftouter join` when you just need to attach extra columns — no row multiplication when the lookup key is unique in the right table.
- The right (lookup) table should be small — a `datatable`, `externaldata`, or pre-summarized result.
- Common use: matching against watchlists — known-bad IPs, blocked domains, allow/deny lists.
- No row multiplication when the lookup table's join key is unique — if duplicate keys exist in the lookup table, rows will multiply as with a join.

**How `lookup` differs from join**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
join   → general purpose, both tables can be large, multiple join types
lookup → for adding columns from a small reference table:
         - right table should be small
         - no row multiplication — assuming the lookup key is unique in the right table
         - use when: "add context from a reference table to each event row"
</pre>

**Examples**


```kusto
// Match email URLs against a threat intelligence table
let ThreatIntel = datatable(Domain:string, ThreatCategory:string, Confidence:string)
[
    "evil-phishing.com",   "Phishing",              "High",
    "malware-host.net",    "Malware",               "High",
    "suspicious-cdn.io",   "C2",                    "Medium",
    "fake-login.org",      "Credential Harvesting", "High"
];
EmailUrlInfo
| where Timestamp > ago(7d)
| lookup kind=leftouter ThreatIntel on $left.UrlDomain == $right.Domain
| where isnotempty(ThreatCategory)
| project Timestamp, NetworkMessageId, UrlDomain, ThreatCategory, Confidence
| take 20
```

```kusto
// Add human-readable error descriptions to Entra sign-in failures
let ErrorCodeMap = datatable(ErrorCode:int, ErrorMeaning:string)
[
    50126, "Invalid credentials — bad username or password",
    50053, "Account locked out",
    50057, "Account disabled",
    50074, "MFA required but not completed",
    50076, "MFA required for this resource",
    53003, "Conditional Access blocked"
];
EntraIdSignInEvents
| where Timestamp > ago(7d)
| where ErrorCode != 0
| lookup kind=leftouter ErrorCodeMap on ErrorCode
| project Timestamp, AccountUpn, Application, IPAddress, ErrorCode, ErrorMeaning
| sort by Timestamp desc
| take 20
```

```kusto
// Map alert severity to response SLA and flag breached alerts
let SLAMapping = datatable(Severity:string, ResponseSLAHours:int, Priority:string)
[
    "High",          1,  "P1",
    "Medium",        4,  "P2",
    "Low",          24,  "P3",
    "Informational", 72, "P4"
];
AlertInfo
| where Timestamp > ago(7d)
| lookup kind=leftouter SLAMapping on Severity
| extend AgeHours    = datetime_diff('hour', now(), Timestamp)
| extend SLABreached = AgeHours > ResponseSLAHours
| where SLABreached
| project Timestamp, Title, Severity, Priority, AgeHours, ResponseSLAHours
| sort by AgeHours desc
| take 20
```

```kusto
// Combine externaldata + lookup for public IOC feed matching
let MaliciousHashes = (
    externaldata(sha256_hash: string)
    [@"https://bazaar.abuse.ch/export/txt/sha256/recent/"]
    with (format='txt')
    | where sha256_hash !startswith "#"
    | project sha256_hash
);
EmailAttachmentInfo
| where Timestamp > ago(7d)
| where isnotempty(SHA256)
| lookup kind=inner MaliciousHashes on $left.SHA256 == $right.sha256_hash
| project Timestamp, SenderFromAddress, RecipientEmailAddress, FileName, SHA256
| take 20
```

[back to top](#kql-intermediate-series)

---

<a id="iif" name="iif"></a>
## iif() / case()

Two operators for conditional logic — `iif()` returns one of two values based on a condition; `case()` evaluates multiple conditions in sequence and returns the first matching result.

### iif()

- Conditional expression returning one of two values.
- `iif(condition, value-if-true, value-if-false)`
- Strictly a single if / else expression. Cannot be chained e.g. if / elseif / elseif / ... / else.

**Examples**

```kusto
IdentityLogonEvents                         // Query identity logon events
| where Timestamp > ago(7d)                 // Limit to last 7 days
| extend                                    // Add a derived risk classification column
    Risk = iif(                             // Conditional logic (if / else)
        ActionType == "LogonFailed",        // If the logon attempt failed
        "HighRisk",                         // Assign high risk
        "Normal"                            // Otherwise assign normal risk
    )
| project-reorder Risk                      // Move the Risk column to the front for visibility

```

```kusto
EmailAttachmentInfo                   // Query email attachment metadata
| where Timestamp > ago(7d)           // Limit to last 7 days
| extend                              // Add a derived size classification column
    IsLarge = iif(                    // Conditional logic (if / else)
        FileSize > 5000000,           // If attachment size is greater than 5 MB
        "Yes",                        // Mark as large
        "No"                          // Otherwise mark as not large
    )
```

```kusto
// Label alerts as actionable or informational
AlertInfo
| where Timestamp > ago(7d)
| extend
    Actionable = iif(
        Severity in ("High", "Medium"),
        "Yes",
        "No"
    )
| project Timestamp, Title, Severity, Actionable
| sort by Actionable asc, Severity asc
```

```kusto
// Label each Entra sign-in as Success or Failure
EntraIdSignInEvents
| where Timestamp > ago(1d)
| extend
    Outcome = iif(
        ErrorCode == 0,
        "Success",
        "Failure"
    )
| project Timestamp, AccountUpn, Application, Country, Outcome
| take 20
```

```kusto
// Label URL clicks as risky or safe
UrlClickEvents
| where Timestamp > ago(7d)
| extend
    RiskLabel = iif(
        ActionType == "ClickBlocked" or IsClickedThrough == true,
        "Risky",
        "Safe"
    )
| project Timestamp, AccountUpn, Url, ActionType, RiskLabel
| take 20
```

### case()

- Multi-condition branching (more flexible than `iif()`).
- Evaluates conditions in order, returns first match. Once a condition matches for a row, the remaining conditions for that row are skipped — each row is evaluated independently.
- Works like an ordered if / elseif chain.

**How `case()` works**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
case(
    condition1, result1,    ← First match wins
    condition2, result2,
    condition3, result3,
    default_result          ← Fallback if nothing matches
)

Example:
case(
    Score > 80, "Critical",
    Score > 50, "High",
    Score > 20, "Medium",
    "Low"                   ← Default
)

Row 1:
  check condition 1 → true → return value → STOP (for this row)

Row 2:
  check condition 1 → false
  check condition 2 → true → return value → STOP (for this row)

Row 3:
  check condition 1 → false
  check condition 2 → false
  check condition 3 → true → return value → STOP (for this row)

</pre>

**Examples**

```kusto
// Categorize emails by attachment count risk
EmailEvents                                          // Query the EmailEvents table
| where Timestamp > ago(7d)                          // Limit to last 7 days
| extend                                             // Add risk classification column
    AttachmentRisk = case(                           // Multi-condition evaluation
        AttachmentCount > 10, "Critical",            // More than 10 attachments
        AttachmentCount > 5, "High",                 // 6-10 attachments
        AttachmentCount > 0, "Medium",               // 1-5 attachments
        "None"                                       // No attachments (default)
    )
| summarize                                          // Aggregate by risk level
    Count = count()
    by AttachmentRisk
| sort by Count desc                                 // Sort by volume
```

```kusto
// Classify delivery outcomes
EmailEvents                                          // Query the EmailEvents table
// | where Timestamp > ago(7d)                          // Limit to last 7 days
| extend                                             // Add delivery classification
    DeliveryOutcome = case(                          // Evaluate delivery location
        DeliveryLocation == "Inbox", "Delivered",
        DeliveryLocation == "Quarantine", "Blocked",
        DeliveryLocation == "JunkFolder", "Junk",
        DeliveryLocation has "Deleted", "Removed",
        "Other"                                      // Default fallback
    )
| summarize                                          // Count by outcome
    EmailCount = count()
    by DeliveryOutcome
```

```kusto
// Risk score sender domains by email volume
EmailEvents                                          // Query the EmailEvents table
| where Timestamp > ago(7d)                          // Limit to last 7 days
| summarize                                          // Count emails per domain
    EmailCount = count()
    by SenderFromDomain
| extend                                             // Add volume-based risk tier
    VolumeTier = case(                               // Classify by email count
        EmailCount > 10000000, "Very High Volume",
        EmailCount > 5000000, "High Volume",
        EmailCount > 1000000, "Medium Volume",
        EmailCount > 100000, "Low Volume",
        "Minimal"                                    // Default
    )
| sort by EmailCount desc
| take 20                                            // Top 20 domains
```

```kusto
// Classify Entra sign-in failures by error code meaning
EntraIdSignInEvents
| where Timestamp > ago(7d)
| where ErrorCode != 0
| extend
    FailureReason = case(
        ErrorCode == 50126, "Invalid credentials",
        ErrorCode == 50053, "Account locked out",
        ErrorCode == 50057, "Account disabled",
        ErrorCode == 50074, "MFA required",
        ErrorCode == 50125, "Password reset in progress",
        "Other failure"
    )
| summarize Count = count() by FailureReason
| sort by Count desc
```

```kusto
// Assign response priority to alerts based on severity + category
AlertInfo
| where Timestamp > ago(7d)
| extend
    Priority = case(
        Severity == "High"   and Category == "Execution", "P1 — Immediate",
        Severity == "High",                               "P2 — Urgent",
        Severity == "Medium",                             "P3 — Normal",
        "P4 — Low"
    )
| project Timestamp, Title, Severity, Category, Priority
| sort by Priority asc
```

```kusto
// Classify post-delivery actions into readable categories
EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| extend
    ActionCategory = case(
        ActionType has "ZAP",    "Automated — ZAP",
        ActionType has "Manual", "Manual — Admin",
        ActionType has "Move",   "Mailbox Move",
        "Other"
    )
| summarize Count = count() by ActionCategory
| sort by Count desc
```

[back to top](#kql-intermediate-series)

---

<a id="parse_json" name="parse_json"></a>
## parse_json()

- Converts JSON strings into queryable dynamic objects.
- Access nested properties with dot notation or brackets.

**How `parse_json()` works**

**Before:** String columns that look like JSON

```string
"{\"key1\":\"value1\",\"nested\":{\"a\":1,\"b\":2}}"
```
**After:** Dynamic object
```json
{
   "key1": "value1",
   "nested": {
     "a": 1,
     "b": 2
   }
}
```

**Access:**
```
Data.key1 = "value1"
Data.nested.a = 1
Data["nested"]["b"] = 2
```

- Identify the dynamic column.
- Use `parse_json()` to convert it to a queryable object.
- Inspect keys if needed: `| take 1 | project Parsed`.
- Flatten fields with `extend` and cast to the correct type.
- Project the clean output.
```kusto
SomeTable
| where Timestamp >= ago(7d)
| where isnotempty(SomeDynamicColumn)
| extend Parsed = parse_json(SomeDynamicColumn)
| extend
    Field1 = tostring(Parsed.Field1),
    Field2 = tostring(Parsed.Field2),
    Field3 = todatetime(Parsed.Field3)
| project 
    Timestamp, 
    Field1, 
    Field2, 
    Field3
```

**Examples**

```kusto
CloudAppEvents
| getschema 
```

```kusto
CloudAppEvents
| extend Data = parse_json(RawEventData)
| sample 5
| project Data
// | project Data.Id, Data.AppId
```

```kusto
CloudAppEvents
| extend Data = parse_json(RawEventData)
| take 1
| project Timestamp, Application, Data
```

```kusto
// check dlp history
let dlp_history =
    CloudAppEvents
    | where Timestamp >= ago(90d)
    | where ActionType =~ "DLPRuleMatch"
    | where Application in ("Microsoft SharePoint Online",
                            "Microsoft OneDrive for Business")
    | where isnotempty(ObjectName)
    | extend Raw = parse_json(RawEventData)
    | extend
        RawIncidentId       = tostring(Raw.IncidentId),
        RawUserId           = tostring(Raw.UserId),
        RawCreationTime     = todatetime(Raw.SharePointMetaData.ItemCreationTime),
        RawLastModifiedTime = todatetime(Raw.SharePointMetaData.ItemLastModifiedTime),
        RawFileID           = tostring(Raw.SharePointMetaData.FileID)
    | mv-expand Policy = Raw.PolicyDetails
    | extend
        RawPolicyId   = tostring(Policy.PolicyId),
        RawPolicyName = tostring(Policy.PolicyName)
    | mv-expand Rule = Policy.Rules
    | extend
        RawRuleId   = tostring(Rule.RuleId),
        RawRuleName = tostring(Rule.RuleName)
    | extend ObjectName = url_decode(ObjectName)
    | project
        DLPTime       = Timestamp,
        DLPAction     = ActionType,
        DLPObjectName = ObjectName,
        DLPUserId     = RawUserId,
        DLPIncidentId = RawIncidentId,
        DLPPolicyId   = RawPolicyId,
        DLPPolicyName = RawPolicyName,
        DLPRuleId     = RawRuleId,
        DLPRuleName   = RawRuleName,
        RawEventData;
dlp_history
```

[back to top](#kql-intermediate-series)

---

<a id="isempty-isnull" name="isempty-isnull"></a>
## isempty() / isnull()

- Check for missing or blank values.
- `isnull()` checks for null only. `isempty()` checks for empty strings and null — it returns true for both.

**Understanding empty vs null**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
┌──────────────────┬─────────────┬─────────────┬─────────────────┐
│ Value            │ isnull()    │ isempty()   │ isnotempty()    │
├──────────────────┼─────────────┼─────────────┼─────────────────┤
│ null             │ true        │ true        │ false           │
│ ""               │ false       │ true        │ false           │
│ "hello"          │ false       │ false       │ true            │
│ "   "            │ false       │ false       │ true            │
└──────────────────┴─────────────┴─────────────┴─────────────────┘
</pre>

<br>

> Use `isnotempty()` to filter out both null and empty strings

**Examples**

```kusto
EmailEvents
| where isempty(SenderFromDomain)
```

```kusto
EmailAttachmentInfo
| where isempty(FileType)
```

```kusto
IdentityLogonEvents
| where isnull(Location)
```

```kusto
// Find alerts with no category assigned
AlertInfo
| where Timestamp > ago(7d)
| where isempty(Category)
| project Timestamp, AlertId, Title, Severity, ServiceSource
```

```kusto
// Find Entra sign-in events with no country data
EntraIdSignInEvents
| where Timestamp > ago(7d)
| where isempty(Country)
| project Timestamp, AccountUpn, Application, IPAddress, ErrorCode
```

```kusto
// Find Teams messages where threat types are empty
MessageEvents
| where Timestamp > ago(7d)
| where isempty(ThreatTypes)
| project Timestamp, TeamsMessageId, SenderEmailAddress, DeliveryAction
```

```kusto
// Find email URLs with no domain recorded
EmailUrlInfo
| where Timestamp > ago(7d)
| where isempty(UrlDomain)
| project Timestamp, NetworkMessageId, Url
```

[back to top](#kql-intermediate-series)

---

<a id="coalesce" name="coalesce"></a>
## coalesce()

- `coalesce(v1, v2, ...)` returns the first non-null value from the argument list.
- Use it to fill in missing data from a fallback field — cleaner than nested `iif(isnull(...), ..., ...)`.

**Examples**

```kusto
// coalesce() — use display name if present, fall back to email address
// SenderDisplayName is sometimes null; fall back to SenderFromAddress
EmailEvents
| where Timestamp > ago(7d)
| extend SenderLabel = coalesce(SenderDisplayName, SenderFromAddress)
| project Timestamp, SenderLabel, SenderFromAddress, Subject
| take 20
```

```kusto
// coalesce() — fill missing AccountDisplayName from AccountUpn
// Display names are not always populated in Entra sign-in events
EntraIdSignInEvents
| where Timestamp > ago(7d)
| where ErrorCode != 0
| extend Identity = coalesce(AccountDisplayName, AccountUpn)
| project Timestamp, Identity, Application, IPAddress, ErrorCode
| sort by Timestamp desc
| take 20
```

```kusto
// coalesce() — cascade across multiple possible identifier fields
// Use when different log sources contribute different identity columns
AlertEvidence
| where Timestamp > ago(7d)
| where EntityType == "Machine"
| extend DeviceLabel = coalesce(DeviceName, tostring(DeviceId), "Unknown")
| project Timestamp, AlertId, DeviceLabel
| take 20
```

[back to top](#kql-intermediate-series)

---

<a id="live-scenario-join" name="live-scenario-join"></a>
## Live scenario: join

### Scenario
You need to investigate emails with suspicious attachments and correlate them with URL click behavior.

### Your mission
1. Find emails with attachments from external senders
2. Join with URL data to see if those emails contained links
3. Check if any recipients clicked those links

### Skills tested
- `join` with multiple tables
- `let` for variable pivoting
- Combining `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo`, `UrlClickEvents`

```kusto
// Try it yourself
```

[back to top](#kql-intermediate-series)

---

<a id="live-scenario-bin-render" name="live-scenario-bin-render"></a>
## Live scenario: bin() and render

### Scenario
Management wants to understand email traffic patterns and identify unusual spikes in activity.

### Your mission
1. Create hourly email volume charts
2. Compare inbound vs outbound patterns
3. Identify peak hours for your organization

### Skills tested
- `bin()` for time bucketing
- `summarize` with multiple aggregations
- `render` for visualization

```kusto
// Try it yourself
```

[back to top](#kql-intermediate-series)

---

<a id="common-gotchas-tips" name="common-gotchas-tips"></a>
## Common gotchas & tips

### Join performance: filter before joining
- Always filter tables with `where` BEFORE joining
- Joining large tables without filtering is slow and may time out

### Dynamic arrays
- `make_set()` returns a dynamic array — use `mv-expand` to flatten
- `has_any()` works with dynamic arrays directly

**Example**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
Subject has_any ("invoice", "payment")

let keywords = dynamic(["invoice", "payment"]);
EmailEvents
| where Subject has_any (keywords)
</pre>

### Join types matter
- `inner` — only matching rows from both tables
- `leftouter` — all from left, matching from right (nulls if no match)
- `leftsemi` — left rows that have a match in the right table; no right columns added
- `leftanti` — rows from left with no match in right (great for finding gaps)

### Empty vs null
- `isempty()` returns true for empty strings and null
- `isnull()` checks for null only
- Use `isnotempty()` to filter out both empty and null

[back to top](#kql-intermediate-series)

---
