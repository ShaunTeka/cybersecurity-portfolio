# 🔵 Microsoft Sentinel Threat Hunting & Command-and-Control Detection Lab

## 📌 Overview

This project demonstrates the deployment of a hybrid security monitoring environment using **Azure Arc**, **Microsoft Sentinel**, **Azure Monitor Agent (AMA)**, and **Azure Machine Learning**.

The objective was to onboard an on-premises Windows Server into Azure, collect security telemetry, simulate a DNS-based Command-and-Control (C2) attack, perform threat hunting using Kusto Query Language (KQL), create hunting and analytics rules, investigate security events, and explore machine learning capabilities within Microsoft Sentinel.

---

## 🎯 Skills Demonstrated

- Azure Arc
- Microsoft Sentinel
- Azure Monitor Agent (AMA)
- Data Collection Rules (DCR)
- Threat Hunting
- Kusto Query Language (KQL)
- MITRE ATT&CK Framework
- Command and Control (C2) Detection
- Incident Investigation
- Analytics Rule Creation
- Search Jobs
- Azure Machine Learning
- MSTICPy
- Security Operations (SOC)

---

# 🖥️ Phase 1: Connect an On-Premises Server to Azure

## Objective

Connect a Windows Server hosted outside Azure to an Azure subscription using Azure Arc.

### Evidence

### Image 01
![Image 01](../../screenshots/image01-connect-server-to-azure.png)
Connected an on-premises Windows Server to Azure using Azure Arc.

### Image 02
Opened Command Prompt and executed the onboarding command:

```powershell
azcmagent connect -g "defender-RG" -l "eastus2" -s "e95997cc-409a-4d9e-b8ee-8cde3721b2bd"
```

### Image 03
Azure authentication prompt generated and requested browser sign-in.

### Image 04
Azure resources and dependencies downloaded automatically.

### Image 05
Azure Arc resources successfully created and the server began connecting.

### Image 06
Executed the following command to verify connectivity:

```powershell
azcmagent show
```

### Image 07
Verification confirmed the Azure Arc agent was connected successfully.

### Outcome

✅ Successfully onboarded an on-premises Windows Server to Azure using Azure Arc.

---

# 🛡️ Phase 2: Connect Azure Arc Server to Microsoft Sentinel

## Objective

Configure Microsoft Sentinel to collect security logs from the Azure Arc-connected server.

### Evidence

### Image 08
Logged into Azure from a client machine.

### Image 09
Navigated to:

**Microsoft Sentinel → Configuration → Data Connectors**

Searched for:

**Windows Security Events via AMA**

### Image 10
Opened the connector page.

### Image 11
Selected:

**+ Create Data Collection Rule**

### Image 12
Created a Data Collection Rule named:

```text
AZWINDCR
```

### Image 13
Selected:

- Subscription
- Resource Group: defender-RG
- Server: WINServer

### Image 14
Retained default event collection settings.

### Image 15
Validation completed successfully.

### Image 16
Successfully deployed:

- Azure Monitor Agent
- Data Collection Rule Association
- AZWINDCR

### Outcome

✅ Successfully connected the Azure Arc server to Microsoft Sentinel.

---

# 🎭 Phase 3: Simulating a DNS Command-and-Control Attack

## Objective

Generate malicious-like DNS traffic for threat hunting exercises.

### Image 17
Created a PowerShell file:

```powershell
notepad c2.ps1
```

### Image 18
Created a new file after Windows could not locate the script.

### Image 19
Added the DNS Command-and-Control simulation script.

```powershell
param(
    [string]$Domain = "microsoft.com",
    [string]$Subdomain = "subdomain",
    [string]$Sub2domain = "sub2domain",
    [string]$Sub3domain = "sub3domain",
    [string]$QueryType = "TXT",
    [int]$C2Interval = 8,
    [int]$C2Jitter = 20,
    [int]$RunTime = 240
)

$RunStart = Get-Date
$RunEnd = $RunStart.addminutes($RunTime)
$x2 = 1
$x3 = 1

Do {
    $TimeNow = Get-Date

    Resolve-DnsName -type $QueryType $Subdomain".$(Get-Random -Minimum 1 -Maximum 999999)."$Domain -QuickTimeout

    if ($x2 -eq 3 ) {
        Resolve-DnsName -type $QueryType $Sub2domain".$(Get-Random -Minimum 1 -Maximum 999999)."$Domain -QuickTimeout
        $x2 = 1
    }
    else {
        $x2 = $x2 + 1
    }

    if ($x3 -eq 7 ) {
        Resolve-DnsName -type $QueryType $Sub3domain".$(Get-Random -Minimum 1 -Maximum 999999)."$Domain -QuickTimeout
        $x3 = 1
    }
    else {
        $x3 = $x3 + 1
    }

    $Jitter = ((Get-Random -Minimum -$C2Jitter -Maximum $C2Jitter) / 100 + 1) + $C2Interval
    Start-Sleep -Seconds $Jitter

}
Until ($TimeNow -ge $RunEnd)
```

### Image 20
Executed the PowerShell script.

### Image 21
Script executed in the background and generated DNS beaconing activity.

### MITRE ATT&CK Mapping

| Tactic | Technique |
|----------|------------|
| Command and Control | T1071.004 – DNS |

### Outcome

✅ Successfully simulated DNS-based Command-and-Control activity.

---

# 🔎 Phase 4: Threat Hunting with KQL

## Objective

Identify suspicious PowerShell executions.

### Image 22
Opened Microsoft Sentinel Logs.

### Image 23
Created the following KQL query:

```kql
let lookback = 2d;

SecurityEvent
| where TimeGenerated >= ago(lookback)
| where EventID == 4688 and Process =~ "powershell.exe"
| extend PwshParam = trim(@"[^/\\]*powershell(.exe)+", CommandLine)
| project TimeGenerated, Computer, SubjectUserName, PwshParam
| summarize min(TimeGenerated), count()
    by Computer, SubjectUserName, PwshParam
| order by count_ desc nulls last
```

### Image 24
Reviewed query results.

### Image 25
Selected the result showing:

```text
-file c2.ps1
```

Added the finding as a bookmark.

### Image 26
Configured:

- Entity Type: Host
- Identifier: Hostname
- Value: Computer
- MITRE Tactic: Command and Control

### Outcome

✅ Successfully detected the simulated PowerShell C2 activity.

---

# 🎯 Phase 5: Creating a Hunting Query

### Image 27
Opened:

**Threat Management → Hunting**

### Image 28
Selected:

**Create New Query**

### Image 29
Created a hunting query named:

```text
PowerShell Hunt
```

Using the same KQL query.

### Image 30
Configured:

- Host Entity Mapping
- HostName Identifier
- Computer Value
- Command and Control ATT&CK Classification

### Image 31
Executed the hunting query.

### Image 32
Reviewed results.

### Outcome

✅ Created a reusable threat hunting query.

---

# 🔍 Phase 6: Investigation

### Image 33
Added results to LiveStream.

### Image 34
Selected:

**Investigate Bookmark**

### Image 35
Opened the investigation graph.

### Image 36
Explored relationships between security events.

### Image 37
Reviewed an existing incident.

### Outcome

✅ Performed a complete Sentinel investigation workflow.

---

# ⚡ Phase 7: Near Real-Time Analytics Rule

### Image 38
Created a new NRT Rule.

### Image 39
Opened the Analytics Rule Wizard.

### Image 40
Configured the detection query.

### Image 41
Validated query results.

### Image 42
Tested using current results.

### Image 43
Reviewed generated graph.

### Image 44
Configured entity mapping:

- Host
- HostName
- Computer

### Image 45
Retained default settings.

### Image 46
Retained default automation settings.

### Image 47
Saved and created the analytics rule.

### Outcome

✅ Created a Near Real-Time detection rule for PowerShell activity.

---

# 🔍 Phase 8: Search Jobs & MITRE ATT&CK Hunting

### Image 48
Created a Search Job.

### Image 49
Searched for:

```text
reg.exe
```

### Image 50
Reviewed query window.

### Image 51
Created Search Job:

```text
searchtablea5be387c-494e-4275-8b8e-b447c07d99f3
```

### Image 52
Created a hunt combining multiple queries.

### Image 53
Filtered active rules.

### Image 54
Selected Hunting Queries.

### Image 55
Reviewed:

**Account Manipulation (T1098)**

### Image 56
Executed selected queries.

### Image 57
Created a new Hunt.

### Image 58
Added filters:

- Persistence
- T1098

### Outcome

✅ Conducted MITRE ATT&CK-based threat hunting.

---

# 🤖 Phase 9: Microsoft Sentinel Notebooks & Azure Machine Learning

### Image 59
Opened Sentinel Notebooks.

### Image 60
Created an Azure Machine Learning Workspace.

### Image 61
Deployment completed successfully.

### Image 62
Selected:

**Getting Started Guide for Microsoft Sentinel ML Notebooks**

### Image 63
Launched Azure Machine Learning Studio.

### Image 64
Created compute instance:

```text
shaunmonwabisiteka
```

### Image 65
Continued compute instance configuration.

### Image 66
Verified notebook execution environment.

### Image 67
Installed MSTICPy.

### Image 68
Generated:

```yaml
msticpyconfig.yaml
```

### Outcome

✅ Integrated Microsoft Sentinel with Azure Machine Learning and MSTICPy.

---

# 🛠️ Technologies Used

- Microsoft Sentinel
- Azure Arc
- Azure Monitor Agent (AMA)
- Azure Monitor
- Azure Machine Learning
- MSTICPy
- Windows Server
- PowerShell
- Kusto Query Language (KQL)

---

# 📚 MITRE ATT&CK Coverage

| Tactic | Technique |
|----------|------------|
| Command and Control | T1071.004 – DNS |
| Persistence | T1098 – Account Manipulation |
| Execution | PowerShell |
| Discovery | Windows Event Monitoring |

---

# 🏆 Key Achievements

✅ Onboarded an on-premises server into Azure using Azure Arc

✅ Connected Microsoft Sentinel to Azure Arc resources

✅ Simulated DNS Command-and-Control activity

✅ Created KQL threat hunting queries

✅ Built reusable hunting content

✅ Investigated events using Sentinel Investigation Graphs

✅ Developed Near Real-Time analytics rules

✅ Conducted MITRE ATT&CK-aligned threat hunting

✅ Integrated Azure Machine Learning with Microsoft Sentinel

✅ Installed and configured MSTICPy for advanced security analytics

---

## 👨‍💻 Author

### Shaun Monwabisi Teka

**Cybersecurity Analyst | SOC Analyst | Threat Hunter | Cloud Security**

- GitHub: [ShaunTeka](https://github.com/ShaunTeka)
- LinkedIn: [shaunmonwabisiteka](https://www.linkedin.com/in/shaunmonwabisiteka)
