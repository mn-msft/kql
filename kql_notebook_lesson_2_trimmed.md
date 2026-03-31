<a id="kql-intermediate-series" name="kql-intermediate-series"></a>
# KQL for Email Security — Intermediate Series

Building on beginner concepts with aggregations, joins, and variables.

**Where to run these queries:** [Microsoft Defender portal](https://security.microsoft.com) → Investigation & response → Hunting → Advanced hunting

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

<a id="toc" name="toc"></a>
# Table of Contents

1. [summarize](#summarize)
2. [count()](#count)
3. [min() / max()](#min-max)
4. [make_set()](#make_set)
5. [make_list()](#make_list)
6. [make_bag()](#make_bag)
7. [dcount()](#dcount)
8. [arg_max() / arg_min()](#arg_max-arg_min)
9. [bin()](#bin)
10. [render](#render)
11. [countif() / sumif() / dcountif()](#countif)
12. [datetime_diff()](#datetime_diff)
13. [let](#let)
14. [pack_array() / pack()](#pack_array-pack)
15. [has_any / has_all](#has_any-has_all)
16. [join](#join)
17. [union](#union)
18. [externaldata](#externaldata)
19. [iif()](#iif)
20. [case()](#case)
21. [parse_json()](#parse_json)
22. [isempty() / isnull()](#isempty-isnull)
23. [Live Scenario: join](#live-scenario-join)
24. [Live Scenario: bin() and render](#live-scenario-bin-render)
25. [Common Gotchas & Tips](#common-gotchas-tips)
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
// Count unique users by application
CloudAppEvents                                  // Query cloud application activity events
| where Timestamp > ago(7d)                     // Limit to events from the last 7 days
| summarize                                     // Aggregate by application
    UniqueUsers = dcount(AccountDisplayName)    // Count unique users per application
    by Application                              // One row per application
| top 10 by UniqueUsers
```

```kusto
// Count attachments by file type
EmailAttachmentInfo                  // Query email attachment metadata
| where Timestamp > ago(7d)          // Limit to attachments from the last 7 days
| summarize                          // Aggregate by file type
    AttachmentCount = count()        // Total number of attachments per file type
    by FileExtension                      // One row per file type
| sort by AttachmentCount desc       // Sort by attachment volume
| take 10                            // Return top 10 file types
// | top 10 by AttachmentCount desc
```

```kusto
// Largest attachment senders (files > 5 MB, last 30 days)
EmailAttachmentInfo                                             // Query email attachment metadata
| where Timestamp > ago(14d)                                    // Limit to attachments from the last 14 days
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
// avg() - average file size by type
EmailAttachmentInfo                             // Query email attachment metadata
| where Timestamp > ago(7d)                     // Limit to attachments from the last 7 days
| summarize                                     // Aggregate size statistics by file type
    AvgSize = round(avg(FileSize), 3),          // Average attachment size (bytes)
    MinSize = min(FileSize),                    // Smallest attachment size
    MaxSize = max(FileSize)                     // Largest attachment size
    by FileExtension                            // One row per file type
| sort by AvgSize                               // Sort by average attachment size
| take 10                                       // Return top 10 file types
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
- Used inside `summarize`. Only valid in aggregation context

**Examples**

```kusto
EmailEvents
| where RecipientEmailAddress == "user@contoso.com"
| where DeliveryLocation contains "Inbox"
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
| summarize count()
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

<a id="min-max" name="min-max"></a>
## min() / max()

- Returns smallest (`min()`) or largest (`max()`) value.
- Common in timestamp or numerical analysis.

**Examples**

```kusto
IdentityLogonEvents                 // Query the IdentityLogonEvents table (each row = a sign-in event)
| summarize                         // Aggregate across all events in the dataset 
    FirstSeen = min(Timestamp),     // Earliest timestamp observed (first time this identity logged on)  
    LastSeen  = max(Timestamp)      // Most recent timestamp observed (last time this identity logged on)
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

[back to top](#kql-intermediate-series)

---

<a id="make_set" name="make_set"></a>
## make_set()

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
CloudAppEvents                              // Query cloud application activity events
| summarize                                 // Aggregate by application
    ActionTypes = make_set(ActionType)      // Collect unique action types per application
    by Application                          // One row per application
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

[back to top](#kql-intermediate-series)

---

<a id="make_list" name="make_list"></a>
## make_list()

- Creates an array of ALL values (including duplicates).
- Use when you need to preserve duplicates or ordering.

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
| sort by NetworkMessageId asc, Timestamp asc
| summarize
    ActionList = make_list(ActionType)
    by NetworkMessageId
```

[back to top](#kql-intermediate-series)

---

<a id="make_bag" name="make_bag"></a>
## make_bag()

- Collects key-value pairs into a JSON object.
- Useful for combining multiple values into one column.
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
    summarize make_bag(pack(Property, Value)) by Sender
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
| extend                                             // Create key-value pair for each row
    EmailDetail = pack(                              // Pack fields into JSON object
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
    FileDetail = pack(FileName, FileSize)            // Pack filename → size mapping
| summarize                                          // Aggregate by message
    AttachmentBag = make_bag(FileDetail)             // Merge into single JSON object
    by NetworkMessageId                              // One row per message
| take 10
```

```kusto
// Build a lookup bag of sender → domain relationships
EmailEvents                                          // Query the EmailEvents table
| where Timestamp > ago(7d)                          // Limit to last 7 days
| extend                                             // Create sender → domain mapping
    SenderMapping = pack(                            // Pack as key-value pair
        SenderFromAddress,                           // Sender email as key
        SenderFromDomain                             // Domain as value
    )
| summarize                                          // Aggregate across all rows
    SenderDomainLookup = make_bag(SenderMapping)     // Merge into lookup dictionary
```

```kusto
// Build file type → SHA256 hash lookup per sender
EmailAttachmentInfo                                  // Query email attachment metadata
| where Timestamp > ago(7d)                          // Limit to last 7 days
| where isnotempty(SHA256)                           // Only attachments with hash values
| extend                                             // Create file type → hash mapping
    HashMapping = pack(FileType, SHA256)             // Pack file type as key, hash as value
| summarize                                          // Aggregate by sender
    FileHashBag = make_bag(HashMapping)              // Merge into lookup dictionary
    by SenderFromAddress                             // One row per sender
| take 10
```

```kusto
// Aggregate user actions per application
CloudAppEvents                                       // Query cloud application events
| where Timestamp > ago(7d)                          // Limit to last 7 days
| extend                                             // Create action → object mapping
    ActionMapping = pack(                            // Pack action details
        ActionType,                                  // Action type as key
        ObjectName                                   // Object affected as value
    )
| summarize                                          // Aggregate by user and app
    ActionsBag = make_bag(ActionMapping)             // Merge into single JSON object
    by AccountDisplayName, Application               // One row per user per app
| take 10
```

```kusto
// Aggregate post-delivery actions and results per message
EmailPostDeliveryEvents                              // Query post-delivery events
| where Timestamp > ago(7d)                          // Limit to last 7 days
| where ActionType != "Dynamic Delivery"
| extend                                             // Create action details mapping
    ActionMapping = pack(                            // Pack action details
        "Action", Action,                            // Action taken on the entity
        "ActionType", ActionType,                    // Type (ZAP, Manual remediation)
        "ActionTrigger", ActionTrigger,              // What triggered it (Admin, ZAP, etc.)
        "ActionResult", ActionResult                 // Result (Success, Error)
    )
| summarize                                          // Aggregate by message and recipient
    ActionsBag = make_bag(ActionMapping)             // Merge into single JSON object
    by NetworkMessageId, RecipientEmailAddress       // One row per message per recipient
| take 10
```

```kusto
// Property bag of entity types and roles per alert
AlertEvidence
| where Timestamp > ago(7d)
| extend
    EvidenceDetail = pack(
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
    FailureDetail = pack(
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
    ClickDetail = pack(
        ActionType, Url
    )
| summarize
    ClickBag = make_bag(ClickDetail)
    by AccountUpn
```

```kusto
EmailEvents
| summarize RecipientCount = count() by 
    SenderFromAddress, 
    RecipientEmailAddress
| summarize RecipientsAndCount = make_bag(
    pack(
        RecipientEmailAddress, 
        RecipientCount
        )
    ) by 
        SenderFromAddress
| take 20
```

[back to top](#kql-intermediate-series)

---

<a id="dcount" name="dcount"></a>
## dcount()

- Counts distinct values efficiently.
- Approximates distinct counts on large data.

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

[back to top](#kql-intermediate-series)

---

<a id="arg_max-arg_min" name="arg_max-arg_min"></a>
## arg_max() / arg_min()

- `arg_max()` returns the row with the maximum value of a column — use for the latest or most recent record per group.
- `arg_min()` returns the row with the minimum value — use for the earliest or first record per group.

**How they work**

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

**Examples**

```kusto
IdentityLogonEvents                     // Query identity logon events
| summarize                             // Aggregate by account UPN
    arg_max(Timestamp, *)               // Select the most recent event and return all columns
    by AccountUpn                       // One row per account
```

```kusto
EmailAttachmentInfo                     // Query email attachment metadata
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
| summarize                                         // Aggregate by account object ID
    arg_max(Timestamp, ActionType, Application)     // Select the most recent action and app
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

**Examples**

**`arg_min()` — Examples**

```kusto
IdentityLogonEvents                  // Query identity logon events
| summarize                          // Aggregate by account UPN
    arg_min(Timestamp, *)            // Select the earliest sign-in event and return all columns
    by AccountUpn                    // One row per user account
```

```kusto
EmailAttachmentInfo                         // Query email attachment metadata
| summarize                                 // Aggregate by recipient email address
    arg_min(FileSize, FileName, FileType)   // Select the smallest attachment and return its details
    by RecipientEmailAddress                // One row per recipient
| sort by FileSize asc                      // Sort recipients by smallest attachment size
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
| summarize                          // Aggregate events into fixed 1-hour time buckets
    MessagesPerHourBlock = count()   // Count number of email events per hour
    by bin(Timestamp, 1h)            // Group events into 1-hour time bins
```

```kusto
CloudAppEvents                       // Query cloud application activity events
| where Timestamp >= ago(14d)
| summarize                          // Aggregate events into fixed 1-day time buckets
    EventsPerDay = count()           // Count number of events per day
    by bin(Timestamp, 1d)            // Group events into 1-day time bins
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
    by bin(Timestamp, 1h)
| sort by Timestamp asc
```

[back to top](#kql-intermediate-series)

---

<a id="render" name="render"></a>
## render

- Adds visualization

**Examples**

```kusto
EmailEvents
| where Timestamp >= ago(1d)
| summarize MessagesPerHourBlock = count() by bin(Timestamp, 1h)
| render columnchart 
```

```kusto
CloudAppEvents
| summarize Count = count() by bin(Timestamp, 1h)
| render timechart
```

```kusto
EmailEvents
| summarize Total = count() by SenderFromDomain
| render barchart
```

```kusto
EmailEvents
| summarize Direction = count() by EmailDirection
| render 
```

```kusto
// Alert volume over time — timechart
AlertInfo
| where Timestamp > ago(7d)
| summarize AlertCount = count() by bin(Timestamp, 1h)
| render timechart
```

```kusto
// Entra sign-in failures by country — barchart
EntraIdSignInEvents
| where Timestamp > ago(7d)
| where ErrorCode != 0
| summarize Failures = count() by Country
| render barchart
```

```kusto
// URL click action breakdown — piechart
UrlClickEvents
| where Timestamp > ago(7d)
| summarize Count = count() by ActionType
| render piechart
```

[back to top](#kql-intermediate-series)

---

<a id="countif" name="countif"></a>
## countif() / sumif() / dcountif()

- Conditional aggregations inside `summarize`.
- `countif()` - count only where condition is true.
- `sumif()` - Sum values only where condition is true.
- `dcountif()` - Count distinct values only where condition is true.
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
| summarize                                                 // Aggregate by sender domain
    HighVolumeSenders = countif(NetworkMessageId != "")     // Count email events with a valid message ID
    by SenderFromDomain                                     // One row per sender domain
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
| where Timestamp > ago(7d)
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
| where Timestamp > ago(7d)
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
    DocSize = sumif(FileSize, FileType has "doc"),   // Word documents
    ZipSize = sumif(FileSize, FileType in ("zip", "rar", "7z"))  // Archives
| extend                                             // Calculate percentages
    ExePct = round(100.0 * ExeSize / TotalSize, 2),
    PdfPct = round(100.0 * PdfSize / TotalSize, 2)
```

```kusto
// Count unique senders by threat category
EmailEvents                                          // Query the EmailEvents table
| where Timestamp > ago(30d)                         // Limit to last 7 days
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

<a id="datetime_diff" name="datetime_diff"></a>
## datetime_diff()

- Calculates the difference between two datetime values.
- Returns difference in specified units (second, minute, hour, day, etc.).
- Useful for measuring time between events.

**How `datetime_diff()` works**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
datetime_diff('unit', datetime1, datetime2)

Units: second, minute, hour, day, week, month, year

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
| where Timestamp between (datetime(2026-01-05) .. datetime(2026-01-07))
| join kind=inner (                                  // Join with URL clicks
    UrlClickEvents
    | where Timestamp between (datetime(2026-01-05) .. datetime(2026-01-07))
    | project                                        // Select click fields
        NetworkMessageId,
        ClickTime = Timestamp,
        AccountUpn,
        IsClickedThrough
    )
    on NetworkMessageId                              // Join on message ID
| extend                                             // Calculate time difference
    MinutesToClick = datetime_diff('minute', ClickTime, Timestamp)
| project                                            // Select output columns
    EmailTime = Timestamp,
    ClickTime,
    MinutesToClick,
    Subject,
    AccountUpn
| sort by MinutesToClick asc                         // Fastest clicks first
| take 20                                            // Top 20
```

```kusto
// Analyze email age in mailbox
EmailEvents                                          // Query email events
| where Timestamp > ago(30d)                         // Limit to last 30 days
| extend                                             // Calculate days since received
    DaysInMailbox = datetime_diff('day', now(), Timestamp)
| summarize                                          // Aggregate by age buckets
    Last24Hours = countif(DaysInMailbox <= 1),
    Last7Days = countif(DaysInMailbox <= 7),
    Last30Days = countif(DaysInMailbox <= 30)
    by DeliveryLocation                              // Group by location
```

```kusto
// Find rapid successive logins (potential credential stuffing)
IdentityLogonEvents                                  // Query identity events
| where Timestamp > ago(1d)                          // Limit to last 24 hours
| sort by AccountUpn, Timestamp asc                  // Order by user and time
| serialize                                          // Enable row functions
| extend                                             // Get previous login time for same user
    PrevTimestamp = prev(Timestamp),
    PrevUser = prev(AccountUpn)
| where AccountUpn == PrevUser                       // Same user consecutive logins
| extend                                             // Calculate seconds between logins
    SecondsBetweenLogins = datetime_diff('second', Timestamp, PrevTimestamp)
| where SecondsBetweenLogins < 60                    // Less than 60 seconds apart
| project                                            // Select output columns
    Timestamp,
    AccountUpn,
    SecondsBetweenLogins,
    Application,
    ActionType
```

```kusto
// How old (in hours) are current open alerts?
AlertInfo
| where Timestamp > ago(7d)
| extend AgeHours = datetime_diff("hour", now(), Timestamp)
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
| extend FailureSpanHours = datetime_diff("hour", LastFailure, FirstFailure)
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
| extend SpanHours = datetime_diff("hour", LastClick, FirstClick)
| where SpanHours > 0
| sort by SpanHours desc
```

[back to top](#kql-intermediate-series)

---

<a id="let" name="let"></a>
## let

- Use `let` to define variables or reusable expressions.
- Variables can hold values, arrays, or table queries.

**How `let` Works**
```kusto
let timeframe = 7d;                     // Value
let badDomains = dynamic(["x","y"]);    // Array
let suspiciousEmails = EmailEvents      // Table query
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
let timeframe = 7d;                     // Define a reusable time window (last 7 days)
EmailEvents                             // Query the EmailEvents table
| where Timestamp > ago(timeframe)      // Filter events using the timeframe variable
| summarize                             // Aggregate by sender domain
    count()                             // Count email events per sender domain
    by SenderFromDomain                 // One row per sender domain
```

```kusto
// create array
let suspiciousDomains = dynamic(["evil.com", "phish.net"]);         // Define a list of suspicious domains
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
    count()                                     // Count failed sign-in events per application
    by Application                              // One row per application
```

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
// Users
Orders
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

<a id="pack_array-pack" name="pack_array-pack"></a>
## pack_array() / pack()

- `pack_array()` combines columns into an **ordered array** — fields referenced by index.
- `pack()` creates a **named JSON object** — fields referenced by key name.

**Examples**

**pack_array() vs pack()**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
pack_array(Sender, Recipient, Subject)
    → ["alice@contoso.com", "bob@fabrikam.com", "Invoice"]

pack("Sender", Sender, "Recipient", Recipient, "Subject", Subject)
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
| where Timestamp >= ago(1d)            // Filter by time
| project                               // Shape the output into a compact structure
    Details = pack_array(               // Create an ordered array of related email fields
        SenderFromAddress,              // Sender email address
        RecipientEmailAddress,          // Recipient email address
        Subject                         // Email subject
    )
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
IdentityLogonEvents                     // Query identity logon events
| project                               // Shape the output into a compact structure
    Summary = pack_array(               // Create an ordered array of identity-related fields
        AccountUpn,                     // User principal name
        Application,                    // Application involved in the logon
        ActionType                      // Logon result/action
    )
```

```kusto
EmailAttachmentInfo                     // Query email attachment metadata
| project                               // Shape the output into a compact structure
    FileSummary = pack_array(           // Create an ordered array of attachment attributes
        FileName,                       // Attachment file name
        FileType,                       // Attachment file type
        FileSize                        // Attachment size (bytes)
    )
```

```kusto
// Bundle key alert fields into a compact ordered array
AlertInfo
| where Timestamp > ago(7d)
| project
    AlertSummary = pack_array(
        Title,        //   [0] Alert title
        Severity,     //   [1] Severity level
        Category,     //   [2] MITRE category
        ServiceSource //   [3] Detecting service
    )
| take 10
```

```kusto
// Bundle sign-in context into a compact array per event
EntraIdSignInEvents
| where Timestamp > ago(1d)
| where ErrorCode != 0
| project
    FailureContext = pack_array(
        AccountUpn,  //   [0] User
        Application, //   [1] App targeted
        Country,     //   [2] Origin country
        ErrorCode    //   [3] Failure reason
    )
| take 10
```

**`pack()` — Examples**

```kusto
// Create a JSON object with email details
EmailEvents                                          // Query the EmailEvents table
| take 5                                             // Limit to 5 rows for demo
| extend                                             // Add a new column with packed JSON
    EmailSummary = pack(                             // Create JSON object with named keys
        "Sender", SenderFromAddress,                 // Key-value pair for sender
        "Recipient", RecipientEmailAddress,          // Key-value pair for recipient
        "Subject", Subject                           // Key-value pair for subject
    )
| project Timestamp, EmailSummary                    // Display timestamp and packed summary
```

```kusto
// Create a JSON object with logon event details
IdentityLogonEvents                                  // Query identity logon events
| take 5                                             // Limit to 5 rows for demo
| extend                                             // Add a new column with packed JSON
    LogonSummary = pack(                             // Create JSON object with named keys
        "User", AccountUpn,                          // Key-value pair for user
        "App", Application,                          // Key-value pair for application
        "Result", ActionType                         // Key-value pair for logon result
    )
| project Timestamp, LogonSummary                    // Display timestamp and packed summary
```

```kusto
// Create a JSON object with attachment metadata
EmailAttachmentInfo                                  // Query email attachment metadata
| take 5                                             // Limit to 5 rows for demo
| extend                                             // Add a new column with packed JSON
    FileSummary = pack(                              // Create JSON object with named keys
        "Name", FileName,                            // Key-value pair for file name
        "Type", FileType,                            // Key-value pair for file type
        "SizeBytes", FileSize                        // Key-value pair for file size
    )
| project NetworkMessageId, FileSummary              // Display message ID and packed summary
```

```kusto
// Create a JSON summary object per alert
AlertInfo
| where Timestamp > ago(7d)
| where Severity == "High"
| take 5
| extend
    AlertSummary = pack(
        "Title",         Title,
        "Severity",      Severity,
        "Category",      Category,
        "ServiceSource", ServiceSource
    )
| project Timestamp, AlertId, AlertSummary
```

```kusto
// Create a JSON object per Entra sign-in failure
EntraIdSignInEvents
| where Timestamp > ago(1d)
| where ErrorCode != 0
| take 5
| extend
    FailureDetail = pack(
        "User",      AccountUpn,
        "App",       Application,
        "Country",   Country,
        "ErrorCode", ErrorCode
    )
| project Timestamp, FailureDetail
```

```kusto
// Create a JSON object per URL click event
UrlClickEvents
| where Timestamp > ago(7d)
| take 5
| extend
    ClickDetail = pack(
        "User",            AccountUpn,
        "Url",             Url,
        "Action",          ActionType,
        "ClickedThrough",  IsClickedThrough
    )
| project Timestamp, ClickDetail
```

[back to top](#kql-intermediate-series)

---

<a id="has_any-has_all" name="has_any-has_all"></a>
## has_any / has_all

- `has_any` finds if any word in a list exists in a string. **Token-based OR**
- `has_all` requires all words to be present. **Token-based AND**
- Different than `in()` as that is an **Exact-match OR**

**Examples**

```kusto
EmailEvents
| where Subject has_any ("invoice", "payment")
```

```kusto
EmailEvents
| where SenderFromAddress has_all ("microsoft","noreply")
```

```kusto
EmailUrlInfo
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
// has_any — Entra sign-ins from automation or scripting apps
EntraIdSignInEvents
| where Timestamp > ago(7d)
| where Application has_any ("PowerShell", "Graph Explorer", "Azure CLI")
| project Timestamp, AccountUpn, Application, IPAddress, ErrorCode
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

[back to top](#kql-intermediate-series)

---

<a id="join" name="join"></a>
## join

- `join` combines two tables based on matching keys.
- Most common Join types: `inner`, `leftouter`, `leftsemi`, `leftanti`.


**Key Takeaways**
- **join adds columns**, not rows
- Rows match where the **join key values are equal**
- Columns from **both tables** can appear in the result
- One-to-many matches cause **row duplication**
- Join kind controls **which rows survive**

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
Returns **left rows that have NO match** in the right table. Useful for finding rows with no match.

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
> Keeps **left rows that have NO match** in right table

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
// leftanti join - find rows with NO match (great for finding gaps)
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
| join kind=leftanti Orders on UserId                           // Keep only users who have NO orders
// Result: Dan, Eve, Frank - users without any orders
```

---

### Duplicates

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

#### Duplicate Join Keys in Security Telemetry

In Microsoft Defender Advanced Hunting tables, it is very common for the join key to appear multiple times.

A good example is: ```NetworkMessageId```

In tables such as:

 - EmailEvents
 - EmailAttachmentInfo
 - EmailUrlInfo

This key does not represent a single row. Instead, it represents a message entity that can fan out into multiple rows.

Sample Scenarios:

| Scenario | Resulting rows |
|----------|----------------|
| 5 recipients | 5 rows |
| 5 attachments | 5 rows |
| 5 recipients × 5 attachments | 25 rows |

Sample Table:

| NetworkMessageId | Recipient | FileName |
| ---------------- | --------- | -------- |
| A                | user1     | file1    |
| A                | user1     | file2    |
| A                | user1     | file3    |
| A                | user2     | file1    |
| A                | user2     | file2    |
| ...              | ...       | ...      |

Deduping the join key e.g. ```NetworkMessageId``` would lead to losing:

 - attachment identity
 - recipient fanout
 - attachment counts
 - investigative context

**Dudupe methods**

```kusto
// group by NMID
EmailAttachmentInfo
| summarize by NetworkMessageId
```

```kusto
// return unique NMID
EmailAttachmentInfo
| distinct NetworkMessageId
```

##### Scenario 1

Preserve Message + Attachment relationship

```kusto
EmailAttachmentInfo
| summarize by NetworkMessageId, FileName
```

```kusto
EmailAttachmentInfo
| distinct NetworkMessageId, FileName
```

##### Scenario 2

Preserve Message + Recipient relationship

```kusto
EmailAttachmentInfo
| summarize by NetworkMessageId, RecipientEmailAddress
```

```kusto
EmailAttachmentInfo
| distinct NetworkMessageId, RecipientEmailAddress
```

##### Scenario 3

Preserve All Details (no dedupe)

```kusto
EmailAttachmentInfo
| project NetworkMessageId, FileName, RecipientEmailAddress
```

##### Scenario 4

Aggregation - One row per message

```kusto
EmailAttachmentInfo
| summarize
    Recipients = make_set(RecipientEmailAddress),
    Attachments = make_set(FileName)
by NetworkMessageId
```

##### Row Explosion

5 x 25 = 125

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

##### Alternatives

Reshape first, one row per mesage on both side?

```kusto
let _Emails =
    EmailEvents
    | where Timestamp > ago (1d)
    | summarize Recipients = make_set(RecipientEmailAddress)
        by NetworkMessageId;
let _Attachments =
    EmailAttachmentInfo
    | where Timestamp > ago (1d)
    | summarize
        Files = make_set(FileName),
        Hashes = make_set(SHA256),
        AttachmentCount = dcount(SHA256)
        by NetworkMessageId;
_Emails
| join kind=inner _Attachments on NetworkMessageId
```

---

### Different Interpretations

```kusto
let Attachmentinfo =                                                // Define a subquery for large attachments
    EmailAttachmentInfo                                             // Query email attachment metadata
    | where Timestamp >= ago(21d)                                   // Limit to attachments from the last x day
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

### Alternative Version

“Top 20 messages by their largest attachment”

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

### Another Alternative Version

“Top 20 unique attachments by size”

- You first dedupe to one row per (NetworkMessageId, FileName).
- Then you join to one row of message metadata per message.
- Then you do top 20 by FileSize.

So the output is:

> Exactly 20 attachment rows (unless fewer exist), representing the largest 20 unique attachments.

```kusto
let Attachments =                                                   // Define unique attachment set
    EmailAttachmentInfo                                             // Query email attachment metadata
    | where Timestamp >= ago(21d)                                   // Limit to last x days
    | summarize                                                     // De-duplicate attachments
        FileSize = max(FileSize)                                    // Defensive max in case of duplicates
        by NetworkMessageId, FileName                               // One row per unique attachment
    | extend                                                        // Add derived columns
        FileSizeMB = round(FileSize / 1024.0 / 1024.0, 2);          // Convert bytes to MB
let MessageInfo =                                                   // Define per-message email metadata
    EmailEvents                                                     // Query email events
    | where Timestamp >= ago(21d)                                   // Match attachment time window
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
| **Row count guarantee** | No — duplicates can reduce distinct results | Can exceed 20 | Yes — exactly 20 |

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

**Key Takeaways**
- **union adds rows**, not columns
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

- Import external CSV or JSON data for comparison.

**Example**

```kusto
externaldata(Domain:string)
[@"https://raw.githubusercontent.com/MicrosoftDocs/microsoft-365-docs/main/domains.csv"]
| join kind=inner (EmailUrlInfo) on $left.Domain == $right.UrlDomain
```

```kusto
let imid =
    externaldata (Message_ID: string) [
    @"https://bwdemoblob.blob.core.windows.net/curated/EmailEvents_20260120_160736.csv"
    h@"?sp=r&st=2026-01-28T15:24:14Z&"
    ]
    with (format='csv', ignorefirstrecord=true)
    | project Message_ID;
imid;
```

```kusto
let imid =
    externaldata (Message_ID:string) [
        @"https://bwdemoblob.blob.core.windows.net/curated/EmailEvents_20260120_160736.csv"
        h@"?sp=r&st=2026-01-28T"
    ]
    with (format='csv', ignorefirstrecord=true)
    | project Message_ID;
EmailEvents
| where Timestamp >= ago(30d)
| where RecipientEmailAddress == "user@contoso.com"
| where InternetMessageId has_any (imid)
```

[back to top](#kql-intermediate-series)

---

<a id="iif" name="iif"></a>
## iif()

- Conditional expression returning one of two values.
- iff(condition, value-if-true, value-if-false)
- Strictly a single if / else expression. Cannot be chained e.g. if / elseif / elseif / ... / else

**Examples**

```kusto
IdentityLogonEvents                         // Query identity logon events
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

[back to top](#kql-intermediate-series)

---

<a id="case" name="case"></a>
## case()

- Multi-condition branching (more flexible than `iif()`).
- Evaluates conditions in order, returns first match. It stops evaluation for that specific row, not all together.
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
| where Timestamp > ago(7d)                          // Limit to last 7 days
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
        EmailCount > 1000, "Very High Volume",
        EmailCount > 500, "High Volume",
        EmailCount > 100, "Medium Volume",
        EmailCount > 10, "Low Volume",
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

Before: AdditionalFields (string)

```string
"{\"key1\":\"value1\",\"nested\":{\"a\":1,\"b\":2}}"
```
After: Dynamic Object
```json
{
   "key1": "value1",
   "nested": {
     "a": 1,
     "b": 2
   }
}
```

Access:  
        Data.key1 = "value1"  
        Data.nested.a = 1  
        Data["nested"]["b"] = 2

**Examples**

**Review MS Bookings Audits**

```kusto
CloudAppEvents
| search "Bookings"
```

```kusto
CloudAppEvents
| extend Data = parse_json(RawEventData)
| take 1
| project Data
// | project Data.Id, Data.AppId
```

```kusto
CloudAppEvents
| extend Data = parse_json(RawEventData)
| take 1
| project Timestamp, Application, Data
```

[back to top](#kql-intermediate-series)

---

<a id="isempty-isnull" name="isempty-isnull"></a>
## isempty() / isnull()

- Check for missing or blank values.
- `isnull()` checks for null values, `isempty()` checks for empty strings.

**Understanding Empty vs Null**

<pre style="background: transparent; padding: 0; margin: 0; font-family: 'JetBrainsMono Nerd Font', monospace; line-height: 1.25;">
┌──────────────────┬─────────────┬─────────────┬─────────────────┐
│ Value            │ isnull()    │ isempty()   │ isnotempty()    │
├──────────────────┼─────────────┼─────────────┼─────────────────┤
│ null             │ true        │ false       │ false           │
│ ""               │ false       │ true        │ false           │
│ "hello"          │ false       │ false       │ true            │
│ "   "            │ false       │ false       │ true            │
└──────────────────┴─────────────┴─────────────┴─────────────────┘

Tip: Use isnotempty() to filter out BOTH null and empty strings
</pre>

**Examples**

```kusto
EmailEvents
| where isnull(SenderFromDomain) or isempty(SenderFromDomain)
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
| where isempty(Category) or isnull(Category)
| project Timestamp, AlertId, Title, Severity, ServiceSource
```

```kusto
// Find Entra sign-in events with no country data
EntraIdSignInEvents
| where Timestamp > ago(7d)
| where isempty(Country) or isnull(Country)
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
| where isempty(UrlDomain) or isnull(UrlDomain)
| project Timestamp, NetworkMessageId, Url
```

[back to top](#kql-intermediate-series)

---

<a id="live-scenario-join" name="live-scenario-join-investigation"></a>
## Live Scenario: join

### Scenario
You need to investigate emails with suspicious attachments and correlate them with URL click behavior.

### Your Mission
1. Find emails with attachments from external senders
2. Join with URL data to see if those emails contained links
3. Check if any recipients clicked those links

### Skills Tested
- `join` with multiple tables
- `let` for variable pivoting
- Combining `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo`, `UrlClickEvents`

```kusto
// Try









```

[back to top](#kql-intermediate-series)

---

<a id="live-scenario-bin-render" name="live-scenario-time-analysis"></a>
## Live Scenario: bin() and render

### Scenario
Management wants to understand email traffic patterns and identify unusual spikes in activity.

### Your Mission
1. Create hourly email volume charts
2. Compare inbound vs outbound patterns
3. Identify peak hours for your organization

### Skills Tested
- `bin()` for time bucketing
- `summarize` with multiple aggregations
- `render` for visualization

```kusto
// Try









```

[back to top](#kql-intermediate-series)

---

<a id="common-gotchas-tips" name="common-gotchas-tips"></a>
## Common Gotchas & Tips

### 1. Join Performance - Filter Before Joining
- Always filter tables with `where` BEFORE joining
- Joining large tables without filtering is slow and may timeout

### 2. Dynamic Arrays
- `make_set()` returns a dynamic array - use `mv-expand` to flatten
- `has_any()` works with dynamic arrays directly

**Example**

```kusto
Subject has_any ("invoice", "payment")

let keywords = dynamic(["invoice", "payment"]);
EmailEvents
| where Subject has_any (keywords)
```

### 3. Join Types Matter
- `inner` - only matching rows from both tables
- `leftouter` - all from left, matching from right (nulls if no match)
- `leftanti` - rows from left with NO match in right (great for finding gaps)

### 4. Empty vs Null
- `isempty()` checks for empty strings
- `isnull()` checks for null values
- Use `isnotempty()` to filter out both empty and null

[back to top](#kql-intermediate-series)
