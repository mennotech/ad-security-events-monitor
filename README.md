# AD Security Events Monitor

A set of PowerShell scripts that monitor Active Directory security events and send HTML-formatted email alerts. The three independent monitors track AD attribute changes, failed sign-in attempts, and file/folder permission changes across one or more Windows servers.

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Scheduling with Task Scheduler](#scheduling-with-task-scheduler)
- [License](#license)

---

## Features

| Script | Events Monitored | Windows Event IDs |
|---|---|---|
| `Get-ADEvents.ps1` | AD object creates, modifications, moves, and deletions | 5136, 5137, 5139, 5141 |
| `Get-FailedSignIns.ps1` | Failed logon attempts and account lockouts | 4625, 4740 |
| `Get-PermissionChanges.ps1` | File and folder permission changes | 4670 |

- Queries Security Event Logs across multiple remote servers in a single run
- Correlates related events to provide old-value / new-value comparisons
- Sends a single HTML email report per script execution (no email sent when there are no events)
- Configurable ignore lists to suppress noise (AD object DNs, specific attribute names)

---

## Prerequisites

- Windows Server 2016 or later (on both the host running the scripts and the monitored servers)
- PowerShell 5.1 or higher
- Active Directory PowerShell module (`RSAT-AD-PowerShell`) installed on the host
- The account running the scripts must have **read access to the Security Event Log** on each monitored server
- WinRM enabled and accessible between the host and each monitored server
- An SMTP server reachable from the host

---

## Installation

1. **Clone the repository** on the server that will run the scripts:

   ```powershell
   git clone https://github.com/mennotech/ad-security-events-monitor.git
   cd ad-security-events-monitor
   ```

2. **Create a settings file** for each monitor you want to use by copying the corresponding template:

   ```powershell
   Copy-Item config\ADEvents-Settings-Template.ps1          config\ADEvents-Settings.ps1
   Copy-Item config\FailedSignIns-Settings-Template.ps1     config\FailedSignIns-Settings.ps1
   Copy-Item config\PermissionChanges-Settings-Template.ps1 config\PermissionChanges-Settings.ps1
   ```

   > **Note:** The `config\*-Settings.ps1` files are excluded from version control via `.gitignore` so your environment-specific values are never committed.

3. **Edit each settings file** as described in the [Configuration](#configuration) section below.

---

## Configuration

### `config\ADEvents-Settings.ps1`

```powershell
# Comma-separated list of servers (domain controllers) to query
$Servers = "dc1,dc2"

# How often the script is scheduled to run, in minutes
# Used to calculate the event log lookback window
$Interval = 5

# Email settings
$SMTPFrom       = 'security-alerts@example.com'
$SMTPTo         = 'admin@example.com'
$SMTPMailServer = 'smtp.example.com'

# Distinguished Names to ignore (supports * wildcards, matched with -like)
$IgnoreDN = @(
    "CN=SomeGroup,OU=Groups,DC=example,DC=com",
    "*CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=com"
)

# Object class / attribute pairs to suppress, in "objectClass:attributeName" format
$IgnoreObjectAttributes = @(
    "computer:servicePrincipalName"
)
```

### `config\FailedSignIns-Settings.ps1`

```powershell
$Servers        = "server1,server2"
$Interval       = 5
$SMTPFrom       = 'security-alerts@example.com'
$SMTPTo         = 'admin@example.com'
$SMTPMailServer = 'smtp.example.com'
```

### `config\PermissionChanges-Settings.ps1`

```powershell
$Servers        = "server1,server2"
$Interval       = 5
$SMTPFrom       = 'security-alerts@example.com'
$SMTPTo         = 'admin@example.com'
$SMTPMailServer = 'smtp.example.com'
```

---

## Usage

Run any script manually from a PowerShell session:

```powershell
# Monitor Active Directory attribute changes
.\Get-ADEvents.ps1

# Monitor failed sign-ins and account lockouts
.\Get-FailedSignIns.ps1

# Monitor file and folder permission changes
.\Get-PermissionChanges.ps1
```

Each script looks back in the Security Event Log by `$Interval` minutes, collects matching events from every server listed in `$Servers`, and sends a single HTML email when events are found. No email is sent when there are no events to report.

### Debug Mode

Pass `-Debug $true` to print verbose output to the console instead of (or in addition to) sending email:

```powershell
.\Get-ADEvents.ps1 -Debug $true
```

---

## Scheduling with Task Scheduler

Each monitor comes with a ready-to-import Task Scheduler XML file. Import a task using the `schtasks` command or the Task Scheduler GUI.

**PowerShell (run as Administrator):**

```powershell
schtasks /create /tn "AD Security Events Monitor"   /xml "AD Security Events Monitor.xml"
schtasks /create /tn "AD Failed Sign Ins Monitor"   /xml "AD Failed Sign Ins Monitor.xml"
schtasks /create /tn "File Security Events Monitor" /xml "File Security Events Monitor.xml"
```

**Task Scheduler GUI:**

1. Open *Task Scheduler* (`taskschd.msc`).
2. In the *Actions* pane, click **Import Task…**
3. Browse to the XML file and click **Open**.
4. On the **General** tab, update the *Security options* to run under an account with the required permissions.
5. Click **OK** to save.

> The default trigger in each XML runs the script every **5 minutes**. Adjust the trigger interval to match the `$Interval` value in your settings file.

---

## License

This project is licensed under the [MIT License](LICENSE).

