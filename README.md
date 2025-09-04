# Azure Unified Audit Tool

This script performs a **comprehensive subscription-wide audit** across Azure.  
It collects information on **Data Collection Rules (DCRs)**, **Security & RBAC**, and **Infrastructure resources**, then exports structured **JSON, CSV, and TXT reports**.  
All results are packaged into a ZIP archive for easy sharing or archiving.  

---

## 📌 Current Coverage

### 🔎 Data Collection Rules (DCRs)
- Lists all Data Collection Rules in each subscription  
- Captures rule name, resource group, location, destination type, and destination resource  

### 🛡️ Security & RBAC
- **Role Assignments** → principal, role definition, scope  
- **Microsoft Sentinel Workspaces** → workspace inventory  
- **Microsoft Defender for Cloud** → protection status for resources  

### 🏗️ Infrastructure Inventory
- Virtual Machines (VMs)  
- Storage Accounts  
- Key Vaults  
- SQL Servers & Databases  
- App Services (Web Apps)  
- Cosmos DB Accounts  
- AKS Clusters  

---

## 📊 Audit Matrix

| **Category** | **Resource / Check** | **Azure CLI Command** | **Collected Fields** |
|--------------|----------------------|------------------------|-----------------------|
| **Data Collection Rules** | Data Collection Rules | `az monitor data-collection rule list` | Name, Resource Group, Location, Destination Type, Destination Resource ID |
| **Security & RBAC** | Role Assignments | `az role assignment list` | Principal Name, Principal ID, Role Definition, Scope |
| | Sentinel Workspaces | `az sentinel list` | Workspace Name, Resource Group, Location |
| | Defender for Cloud Coverage | `az security resource list` | Resource ID, Resource Type, Protection Status |
| **Infrastructure** | Virtual Machines (VMs) | `az vm list` | Name, Resource Group, Location, VM Size, OS Type |
| | Storage Accounts | `az storage account list` | Name, Resource Group, Location, Kind, SKU |
| | Key Vaults | `az keyvault list` | Name, Resource Group, Location, SKU |
| | SQL Servers | `az sql server list` | Name, Resource Group, Location |
| | SQL Databases | `az sql db list` | Name, Server, Resource Group, Location |
| | App Services (Web Apps) | `az webapp list` | Name, Resource Group, Location |
| | Cosmos DB Accounts | `az cosmosdb list` | Name, Resource Group, Location, Kind |
| | AKS Clusters | `az aks list` | Name, Resource Group, Location, Kubernetes Version |

---

## ➕ Potential Future Coverage

The script can be extended to capture additional resources:

### 🔐 Security / Governance
- Policy Assignments (`az policy assignment list`)  
- Policy Compliance (`az policy state list`)  
- Management Locks (`az lock list`)  
- PIM Role Activations  

### 🌐 Networking
- Public IPs (`az network public-ip list`)  
- NSGs (`az network nsg list`)  
- Firewalls (`az network firewall list`)  
- Application Gateways (`az network application-gateway list`)  
- Load Balancers (`az network lb list`)  
- VNets & Subnets (`az network vnet list`)  

### ☁️ Platform Services
- Azure Functions (`az functionapp list`)  
- Event Hubs (`az eventhubs namespace list`)  
- Service Bus (`az servicebus namespace list`)  
- API Management (`az apim list`)  
- Logic Apps (`az logicapp list`)  

### 🗄️ Data & Storage
- Blob/File Containers (`az storage container list`)  
- Managed Disks (`az disk list`)  

### 🔍 Monitoring / Logging
- Log Analytics Workspaces (`az monitor log-analytics workspace list`)  
- Diagnostic Settings (`az monitor diagnostic-settings list`)  

---

## 📂 Example Output

