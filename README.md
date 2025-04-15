Features
Prompts for Azure Subscription, Resource Group, and Sentinel Workspace

Checks Azure role assignments

Gathers data from key services:

Sentinel (Data Connectors, Incidents, Alert Rules)

Networking (VNets, Firewalls)

Compute (VMs, AKS)

Storage (Storage Accounts, Redis, Cosmos DB)

Integration (Logic Apps, API Connections, API Management)

Identity (App Registrations, Key Vaults)

Data Explorer Clusters & Databases

Outputs formatted CSVs for each resource type

Creates an error log for failed operations

Automatically zips the results for easy sharing

🧰 Prerequisites
Ensure the following tools are installed and configured:

Azure CLI (v2.0+)

jq (for JSON processing)

zip (for compressing results)

Logged into Azure via az login

🚀 Usage
Download and make the script executable:

bash
Copy
Edit
chmod +x azure_sentinel_audit.sh
Run the script:

bash
Copy
Edit
./azure_sentinel_audit.sh
Follow the prompts to input:

Your Azure Subscription ID

Your Azure Resource Group name

Your Azure Sentinel Workspace name

When completed:

Results are stored in the ./audit_results/ directory

A audit_results.zip file is created for distribution

📁 Output
The script generates one CSV per resource category, including:

roles_audit.csv

data_connectors_audit.csv

incidents_audit.csv

analytics_rules_audit.csv

audit_logs_audit.csv

...and more

Additionally:

error_log.csv: Captures any failed operations with error messages.

📦 Required Azure CLI Extensions
The script checks for and installs the following extensions if missing:

sentinel

log-analytics

kusto

monitor-control-service

⚠️ Notes
You must have appropriate permissions in the provided Azure subscription.

The script currently focuses on a single resource group and workspace.

For larger environments, consider modifying the script to iterate across multiple resource groups or subscriptions.

🧹 Cleanup
All temporary files are retained unless manually deleted. You can remove them with:

bash
Copy
Edit
rm -rf audit_results audit_results.zip
