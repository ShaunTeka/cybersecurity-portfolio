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

### Connecting an on-premises Windows Server to Azure using Azure Arc.
![Azure Arc Server Connection](screenshots/image01-azure-arc-connect-server.png)


### Opened Command Prompt and executed the onboarding command:
![Azure Arc Onboarding Command](screenshots/image02-azure-arc-onboarding-command.png)
```powershell
azcmagent connect -g "defender-RG" -l "eastus2" -s "e95997cc-409a-4d9e-b8ee-8cde3721b2bd"
```

### Azure authentication prompt generated and requested browser sign-in.
![Azure Authentication Prompt](screenshots/image03-azure-authentication-prompt.png)

### Azure resources and dependencies downloaded automatically.
![Azure Resource Download](screenshots/image04-azure-resource-download.png)

### Azure Arc resources successfully created and the server began connecting.
![Azure Arc Resource Creation](screenshots/image05-azure-arc-resource-creation.png)

### Executed the following command to verify connectivity:
![AZCMAGENT Show Command](screenshots/image06-azcmagent-show-command.png)

```powershell
azcmagent show
```

### Verification confirmed the Azure Arc agent was connected successfully.
![Azure Arc Agent Connected](screenshots/image07-azure-arc-agent-connected.png)

### Outcome

✅ Successfully onboarded an on-premises Windows Server to Azure using Azure Arc.

---

# 🛡️ Phase 2: Connect Azure Arc Server to Microsoft Sentinel

## Objective

Configure Microsoft Sentinel to collect security logs from the Azure Arc-connected server.

### Evidence

### Logged into Azure from a client machine.
![Azure Client Machine](screenshots/image08-azure-client-machine-login.png)

### Navigated to:
![Sentinel Data Connectors Search](screenshots/image09-sentinel-data-connectors-search.png)
**Microsoft Sentinel → Configuration → Data Connectors**

Searched for:

**Windows Security Events via AMA**

### Opened the connector page.
![Windows Security Events Ama](screenshots/image10-windows-security-events-ama.png)

### Selected:

**+ Create Data Collection Rule**
![Create Data Collection Rule](screenshots/image11-create-data-collection-rule.png)

### Created a Data Collection Rule named:

```text
AZWINDCR
```
![AZWINDCR Rule Name](screenshots/image12-azwindcr-rule-name.png)

### Selected:

- Subscription
- Resource Group: defender-RG
- Server: WINServer
![Select Windserver Resource](screenshots/image13-select-winserver-resource.png)

### Retained default event collection settings.
![Data Collection Settings](screenshots/image14-data-collection-settings.png)

### Validation completed successfully.
![Data Collection Validation](screenshots/image15-data-collection-validation.png)

### Successfully deployed:

- Azure Monitor Agent
- Data Collection Rule Association
- AZWINDCR
![Ama Installation Success](screenshots/image16-ama-installation-success.png)

### Outcome

✅ Successfully connected the Azure Arc server to Microsoft Sentinel.

---

# 🎭 Phase 3: Simulating a DNS Command-and-Control Attack

## Objective

Generate malicious-like DNS traffic for threat hunting exercises.

### Created a PowerShell file:

```powershell
notepad c2.ps1
```
![Create c2 Script](screenshots/image17-create-c2-script.png)

### Created a new file after Windows could not locate the script.
![Create New c2 File](screenshots/image18-create-new-c2-file.png)

### Added the DNS Command-and-Control simulation script.

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
![Powershell Script](screenshots/image19-c2-powershell-script.png)

### Executed the PowerShell script.
![Execute c2 Script](screenshots/image20-execute-c2-script.png)

### Script executed in the background and generated DNS beaconing activity.
![c2 Background Execution](screenshots/image21-c2-background-execution.png)

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

### Opened Microsoft Sentinel Logs.
![Open Sentinel Logs](screenshots/image22-open-sentinel-logs.png)

### Created the following KQL query:

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
![Open Sentinel Logs](screenshots/image23-powershell-kql-query.png)


### Reviewed query results.
![KQL Query Results](screenshots/image24-kql-query-results.png)

### Selected the result showing:

```text
-file c2.ps1
```
![Bookmark c2 Activity](screenshots/image25-bookmark-c2-activity.png)

Added the finding as a bookmark.

### Configured:

- Entity Type: Host
- Identifier: Hostname
- Value: Computer
- MITRE Tactic: Command and Control

![Entity Mapping Command Control](screenshots/image26-entity-mapping-command-control.png)


### Outcome

✅ Successfully detected the simulated PowerShell C2 activity.

---

# 🎯 Phase 5: Creating a Hunting Query

### Opened:

**Threat Management → Hunting**
![Open Hunting Pagel](screenshots/image27-open-hunting-page.png)

### Selected:

**Create New Query**
![Create Hunting Query](screenshots/image28-create-hunting-query.png)


### Created a hunting query named:

```text
PowerShell Hunt
```
![Powershell Hunt Query](screenshots/image29-powershell-hunt-query.png)

Using the same KQL query.

### Configured:

- Host Entity Mapping
- HostName Identifier
- Computer Value
- Command and Control ATT&CK Classification

![Host Entity Mapping](screenshots/image30-host-entity-mapping.png)

### Executed the hunting query.
![Run Hunting Query](screenshots/image31-run-hunting-query.png)

### Reviewed results.
![Hunting Query Results](screenshots/image32-hunting-query-results.png)

### Outcome

✅ Created a reusable threat hunting query.

---

# 🔍 Phase 6: Investigation

### Added results to LiveStream.
![Add To Livestream](screenshots/image33-add-to-livestream.png)

### Selected:

**Investigate Bookmark**
![Investigate Bookmark](screenshots/image34-investigate-bookmark.png)

### Opened the investigation graph.
![Investigate Graph](screenshots/image35-investigation-graph.png)

### Explored relationships between security events.
![Security Event Analysis](screenshots/image36-security-event-analysis.png)

### Reviewed an existing incident.
![Existing Incident](screenshots/image37-existing-incident.png)

### Outcome

✅ Performed a complete Sentinel investigation workflow.

---

# ⚡ Phase 7: Near Real-Time Analytics Rule

### Created a new NRT Rule.
![Create NRT Rule](screenshots/image38-create-nrt-rule.png)

### Image 39
Opened the Analytics Rule Wizard.
![Analytics Rule Wizard](screenshots/image39-analytics-rule-wizard.png)

### Configured the detection query.
![NRT Rule Query](screenshots/image40-nrt-rule-query.png)


### Validated query results.
![Query Validation Results](screenshots/image41-query-validation-results.png)


### Tested using current results.
![Test Current Results](screenshots/image42-test-current-results.png)


### Reviewed generated graph.
![Rule Test Graph](screenshots/image43-rule-test-graph.png)


### Configured entity mapping:

- Host
- HostName
- Computer
![Host Entity Mapping Rule](screenshots/image44-host-entity-mapping-rule.png)

### Retained default settings.
![Default Rule Settings](screenshots/image45-default-rule-settings.png)

### Retained default automation settings.
![Default Automation Settings](screenshots/image46-default-automation-settings.png)

### Saved and created the analytics rule.
![Save Analytics Rule](screenshots/image47-save-analytics-rule.png)


### Outcome

✅ Created a Near Real-Time detection rule for PowerShell activity.

---

# 🔍 Phase 8: Search Jobs & MITRE ATT&CK Hunting

### Created a Search Job.
![Create Search Job](screenshots/image48-create-search-job.png)

### Searched for:

```text
reg.exe
```
![Search Reg Exe](screenshots/image49-search-reg-exe.png)

### Reviewed query window.
![Search Job Query Window](screenshots/image50-search-job-query-window.png)


### Created Search Job:

```text
searchtablea5be387c-494e-4275-8b8e-b447c07d99f3
```
![Search Job Results Table](screenshots/image51-search-job-results-table.png)

### Created a hunt combining multiple queries.
![Create Mitre Hunt](screenshots/image52-create-mitre-hunt.png)

### Filtered active rules.
![Filter Active Rules](screenshots/image53-filter-active-rules.png)

### Selected Hunting Queries.
![Filter Hunting Queries](screenshots/image54-filter-hunting-queries.png)

### Reviewed:

**Account Manipulation (T1098)**
![Account Manipulation Technique](screenshots/image55-account-manipulation-technique.png)

### Executed selected queries.
![Run Selected Queries](screenshots/image56-run-selected-queries.png)

### Created a new Hunt.
![Create New Hunt](screenshots/image57-create-new-hunt.png)

### Added filters:

- Persistence
- T1098
![Persistence T1098 Filters](screenshots/image58-persistence-t1098-filters.png)

### Outcome

✅ Conducted MITRE ATT&CK-based threat hunting.

---

# 🤖 Phase 9: Microsoft Sentinel Notebooks & Azure Machine Learning

### Opened Sentinel Notebooks.
![Open Sentinel Notebooks](screenshots/image59-open-sentinel-notebooks.png)

### Created an Azure Machine Learning Workspace.
![Create Azure ML Workspace](screenshots/image60-create-azure-ml-workspace.png)

### Deployment completed successfully.
![Azure ML Deployment Complete](screenshots/image61-azure-ml-deployment-complete.png)

### Selected:

**Getting Started Guide for Microsoft Sentinel ML Notebooks**
![Sentinel Notebook Template](screenshots/image62-sentinel-notebook-template.png)

### Launched Azure Machine Learning Studio.
![Launch Azure ML Studio](screenshots/image63-launch-azure-ml-studio.png)

### Created compute instance:

```text
shaunmonwabisiteka
```
![Create Compute Instance](screenshots/image64-create-compute-instance.png)

### Continued compute instance configuration.
![Configure Compute Instance](screenshots/image65-configure-compute-instance.png)

### Verified notebook execution environment.
![Notebook Execution Environment](screenshots/image66-notebook-execution-environment.png)

### Installed MSTICPy.
![Install Msticpy](screenshots/image67-install-msticpy.png)

### Generated:

```yaml
msticpyconfig.yaml
```
![MTICPY](screenshots/image68-msticpy-config-created.png)
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

