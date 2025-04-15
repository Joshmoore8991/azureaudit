#!/bin/bash

# Fix any Windows line endings (CRLF) to Unix line endings (LF)
sed -i -e 's/\r$//' "$0"

# Prompt user to enter required variables
read -p "Please enter your Azure Subscription ID: " SUBSCRIPTION_ID
read -p "Please enter your Azure Resource Group name: " RESOURCE_GROUP
read -p "Please enter your Azure Sentinel Workspace name: " WORKSPACE_NAME

# Define output directory and files
OUTPUT_DIR="./audit_results"
mkdir -p "$OUTPUT_DIR"

declare -A OUTPUT_FILES
declare -A HEADERS

# File headers and output files definition
OUTPUT_FILES=(
 ["roles"]="$OUTPUT_DIR/roles_audit.csv"
 ["data_connectors"]="$OUTPUT_DIR/data_connectors_audit.csv"
 ["incidents"]="$OUTPUT_DIR/incidents_audit.csv"
 ["analytics_rules"]="$OUTPUT_DIR/analytics_rules_audit.csv"
 ["logic_apps_playbooks"]="$OUTPUT_DIR/logic_apps_playbooks_audit.csv"
 ["audit_logs"]="$OUTPUT_DIR/audit_logs_audit.csv"
 ["storage_accounts"]="$OUTPUT_DIR/storage_accounts_audit.csv"
 ["function_apps"]="$OUTPUT_DIR/function_apps_audit.csv"
 ["adx_clusters"]="$OUTPUT_DIR/adx_clusters_audit.csv"
 ["adx_databases"]="$OUTPUT_DIR/adx_databases_audit.csv"
 ["vnets"]="$OUTPUT_DIR/vnets_audit.csv"
 ["app_service_plans"]="$OUTPUT_DIR/app_service_plans_audit.csv"
 ["vms"]="$OUTPUT_DIR/vms_audit.csv"
 ["api_connections"]="$OUTPUT_DIR/api_connections_audit.csv"
 ["app_registrations"]="$OUTPUT_DIR/app_registrations_audit.csv"
 ["firewalls"]="$OUTPUT_DIR/firewalls_audit.csv"
 ["sql_databases"]="$OUTPUT_DIR/sql_databases_audit.csv"
 ["kubernetes_services"]="$OUTPUT_DIR/kubernetes_services_audit.csv"
 ["cosmos_dbs"]="$OUTPUT_DIR/cosmos_dbs_audit.csv"
 ["redis_caches"]="$OUTPUT_DIR/redis_caches_audit.csv"
 ["api_management_services"]="$OUTPUT_DIR/api_management_services_audit.csv"
 ["key_vaults"]="$OUTPUT_DIR/key_vaults_audit.csv"
 ["error_log"]="$OUTPUT_DIR/error_log.csv"
)

HEADERS=(
 ["roles"]="RoleName,Scope,PrincipalType,PrincipalName"
 ["data_connectors"]="DataConnector,Name,Kind,Location"
 ["incidents"]="Incident,Title,Status,Severity,Location"
 ["analytics_rules"]="AnalyticsRule,Name,Enabled,Query,TriggerStatus,Location"
 ["logic_apps_playbooks"]="LogicAppPlaybook,Name,State,Location"
 ["audit_logs"]="AuditLog,OperationName,Status,EventTimestamp,Location,ErrorMessage"
 ["storage_accounts"]="StorageAccount,Name,Type,Location"
 ["function_apps"]="FunctionApp,Name,ResourceGroup,Location"
 ["adx_clusters"]="ADXCluster,Name,Location,ResourceGroup"
 ["adx_databases"]="ADXDatabase,ClusterName,DatabaseName,Location,ResourceGroup"
 ["vnets"]="VNet,Name,Location,ResourceGroup"
 ["app_service_plans"]="AppServicePlan,Name,Location,ResourceGroup"
 ["vms"]="VM,Name,Location,ResourceGroup,Size"
 ["api_connections"]="APIConnection,Name,Location,ResourceGroup"
 ["app_registrations"]="AppRegistration,DisplayName,AppId,ObjectId"
 ["firewalls"]="Firewall,Name,Location,ResourceGroup"
 ["sql_databases"]="SQLDatabase,Name,Location,ResourceGroup"
 ["kubernetes_services"]="KubernetesService,Name,Location,ResourceGroup"
 ["cosmos_dbs"]="CosmosDB,Name,Location,ResourceGroup"
 ["redis_caches"]="RedisCache,Name,Location,ResourceGroup"
 ["api_management_services"]="APIManagementService,Name,Location,ResourceGroup"
 ["key_vaults"]="KeyVault,Name,Location,ResourceGroup"
 ["error_log"]="Operation,ErrorMessage"
)

# Create the output CSV files and add headers
for key in "${!OUTPUT_FILES[@]}"; do
 echo "${HEADERS[$key]}" > "${OUTPUT_FILES[$key]}"
done

# Install required Azure CLI extensions if not installed
echo "Checking and installing required Azure CLI extensions..."
EXTENSIONS=("sentinel" "monitor-control-service" "log-analytics" "kusto")
for EXT in "${EXTENSIONS[@]}"; do
 az extension add --name "$EXT" --yes
done

# Login and set subscription
echo "Authenticating and setting subscription..."
az account set --subscription "$SUBSCRIPTION_ID"

# Function to check role assignments and write to CSV
check_and_output_permissions() {
 local scope="$1"
 local output_file="$2"
 
 role_assignment=$(az role assignment list --scope "$scope" --output json --query "[].{RoleName:roleDefinitionName, Scope:scope, PrincipalType:principalType, PrincipalName:principalName}" 2>&1)
 
 if [ $? -eq 0 ]; then
 echo "$role_assignment" | jq -r '.[] | ["\(.RoleName)", "\(.Scope)", "\(.PrincipalType)", "\(.PrincipalName)"] | @csv'  >>   "$output_file"
 else
 echo "Error checking permissions at scope $scope: $role_assignment"
 echo "check_permissions,$role_assignment"  >>   "${OUTPUT_FILES["error_log"]}"
 fi
}

# Your user principal
USER_EMAIL=$(az account show --query "user.name" -o tsv)

# Check permissions
check_and_output_permissions "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP" "${OUTPUT_FILES["roles"]}"
check_and_output_permissions "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.OperationalInsights/workspaces/$WORKSPACE_NAME" "${OUTPUT_FILES["roles"]}"

# Function to list Azure Data Explorer clusters and save results
list_adx_clusters() {
 echo "Fetching Azure Data Explorer Clusters..."
 result=$(az kusto cluster list --resource-group "$RESOURCE_GROUP" --output json 2>&1)
 if [ $? -eq 0 ]; then
 echo "$result" | jq -r '.[] | ["ADXCluster", .name, .location, .resourceGroup] | @csv'  >>   "${OUTPUT_FILES["adx_clusters"]}"
 check_for_results "${OUTPUT_FILES["adx_clusters"]}"
 else
 echo "Error fetching ADX Clusters: $result"
 echo "list_adx_clusters,$result"  >>   "${OUTPUT_FILES["error_log"]}"
 fi
}

# Function to list Azure Data Explorer databases and save results
list_adx_databases() {
 echo "Fetching Azure Data Explorer Databases..."
 clusters=$(az kusto cluster list --resource-group "$RESOURCE_GROUP" --query "[].name" -o tsv 2>&1)
 if [ $? -eq 0 ]; then
 for cluster in $clusters; do
 result=$(az kusto database list --cluster-name "$cluster" --resource-group "$RESOURCE_GROUP" --output json 2>&1)
 if [ $? -eq 0 ]; then
 echo "$result" | jq -r --arg cluster "$cluster" '.[] | ["ADXDatabase", $cluster, .name, .location, .resourceGroup] | @csv'  >>   "${OUTPUT_FILES["adx_databases"]}"
 check_for_results "${OUTPUT_FILES["adx_databases"]}"
 else
 echo "Error fetching ADX Databases for cluster $cluster: $result"
 echo "list_adx_databases,$result"  >>   "${OUTPUT_FILES["error_log"]}"
 fi
 done
 else
 echo "Error fetching ADX Clusters: $clusters"
 echo "list_adx_databases,$clusters"  >>   "${OUTPUT_FILES["error_log"]}"
 fi
}

# General function to list resources and save results
run_list_command() {
 local category="$1"
 local command="${LIST_COMMANDS[$category]}"
 
 # Output and result handling
 local result
 result=$(eval "$command" 2>&1)
 if [ $? -eq 0 ]; then
 echo "$result" | jq -r ".[] | [\"$category\", .name, .location, .resourceGroup] | @csv"  >>   "${OUTPUT_FILES[$category]}"
 check_for_results "${OUTPUT_FILES[$category]}"
 else
 echo "Error executing $category: $result"
 echo "$category,$result"  >>   "${OUTPUT_FILES["error_log"]}"
 fi
}

# Define the commands for each category of resources
declare -A LIST_COMMANDS
LIST_COMMANDS=(
 ["data_connectors"]="az sentinel data-connector list --resource-group \$RESOURCE_GROUP --workspace-name \$WORKSPACE_NAME --output json"
 ["incidents"]="az sentinel incident list --resource-group \$RESOURCE_GROUP --workspace-name \$WORKSPACE_NAME --query '[].{Title:title, Status:status, Severity:severity}' --output json"
 ["analytics_rules"]="az sentinel alert-rule list --resource-group \$RESOURCE_GROUP --workspace-name \$WORKSPACE_NAME --output json"
 ["logic_apps_playbooks"]="az logic workflow list --resource-group \$RESOURCE_GROUP --output json"
 ["audit_logs"]="az monitor activity-log list --resource-group \$RESOURCE_GROUP --output json"
 ["storage_accounts"]="az storage account list --resource-group \$RESOURCE_GROUP --output json"
 ["function_apps"]="az functionapp list --resource-group \$RESOURCE_GROUP --output json"
 ["vnets"]="az network vnet list --subscription \$SUBSCRIPTION_ID --output json"
 ["app_service_plans"]="az appservice plan list --resource-group \$RESOURCE_GROUP --output json"
 ["vms"]="az vm list --resource-group \$RESOURCE_GROUP --output json"
 ["api_connections"]="az resource list --resource-group \$RESOURCE_GROUP --resource-type Microsoft.Web/connections --output json"
 ["app_registrations"]="az ad app list --output json"
 ["firewalls"]="az network firewall list --resource-group \$RESOURCE_GROUP --output json"
 ["sql_databases"]="az sql db list --resource-group \$RESOURCE_GROUP --output json"
 ["kubernetes_services"]="az aks list --resource-group \$RESOURCE_GROUP --output json"
 ["cosmos_dbs"]="az cosmosdb list --resource-group \$RESOURCE_GROUP --output json"
 ["redis_caches"]="az redis list --resource-group \$RESOURCE_GROUP --output json"
 ["api_management_services"]="az apim list --resource-group \$RESOURCE_GROUP --output json"
 ["key_vaults"]="az keyvault list --resource-group \$RESOURCE_GROUP --output json"
)

# Function to check if the output file contains results
check_for_results() {
 local file="$1"
 if ; then
 echo "No results"  >>   "$file"
 fi
}

# Run the commands for each type of resource
for category in "${!LIST_COMMANDS[@]}"; do
 echo "Fetching ${category^}..."
 run_list_command "$category"
done

# Run ADX specific functions
list_adx_clusters
list_adx_databases

# Zip all results into a final output zip file
echo "Compressing results into audit_results.zip..."
zip -r audit_results.zip ./audit_results/*

echo "Audit completed! All results have been exported to $OUTPUT_DIR and compressed into audit_results.zip."
