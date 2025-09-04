#!/bin/bash

# Unified Azure Security & Infrastructure Audit Script
# Combines DCR analysis, RBAC/Defender auditing, and full Azure infrastructure audit
set -e

# Fix any Windows line endings
sed -i -e 's/\r$//' "$0" 2>/dev/null || true

# Configuration
OUTPUT_DIR="azure_audit_$(date +%Y%m%d_%H%M%S)"
SUBSCRIPTION_FILTER=""
RESOURCE_GROUP_FILTER=""
WORKSPACE_NAME_FILTER=""

# Audit selections
AUDIT_DCRS=false
AUDIT_RBAC_SECURITY=false
AUDIT_FULL_INFRASTRUCTURE=false
AUDIT_ALL=false
INTERACTIVE_MODE=false
CREATE_ZIP=true
EXPORT_CSV=true

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Logging functions
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}" >&2
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}" >&2
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
    exit 1
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}" >&2
}

# Usage
usage() {
    echo -e "${CYAN}Azure Security & Infrastructure Audit Script${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Audit Modes:"
    echo "  --dcr-audit           Data Collection Rules analysis & cost optimization"
    echo "  --security-audit      RBAC & Microsoft Defender for Cloud analysis"  
    echo "  --infrastructure-audit Complete Azure infrastructure inventory"
    echo "  --all                 All audit types (DCR + Security + Infrastructure)"
    echo ""
    echo "Configuration:"
    echo "  -s, --subscription    Specific subscription ID"
    echo "  -r, --resource-group  Focus on specific resource group"
    echo "  -w, --workspace       Focus on specific Log Analytics workspace"
    echo "  -o, --output          Output directory (default: azure_audit_TIMESTAMP)"
    echo ""
    echo "Options:"
    echo "  -i, --interactive     Interactive mode with menu selection"
    echo "  --no-zip             Don't create final ZIP archive"
    echo "  --no-csv             Don't export CSV files"
    echo "  --list-subs          List accessible subscriptions"
    echo "  -h, --help           Show this help"
    echo ""
    echo "Examples:"
    echo "  $0                                          # Prompts for subscription, RG, workspace"
    echo "  $0 -i                                       # Interactive mode with menu"
    echo "  $0 -s 'sub-id' -r 'rg-name' -w 'workspace' # All parameters specified"
    echo "  $0 --security-audit -s 'sub' -r 'rg' -w 'ws' # Security audit only"
    exit 1
}

# Interactive menu system
show_interactive_menu() {
    clear
    echo -e "${CYAN}================================================${NC}"
    echo -e "${CYAN}    Azure Security & Infrastructure Audit${NC}"
    echo -e "${CYAN}================================================${NC}"
    echo ""
    echo -e "${PURPLE}Select Audit Components:${NC}"
    echo ""
    echo "  1) 🔍 DCR Audit Only"
    echo "     Data Collection Rules, log sources, cost optimization"
    echo ""
    echo "  2) 🔐 Security Audit Only" 
    echo "     RBAC analysis, Defender alerts, security recommendations"
    echo ""
    echo "  3) 🏗️ Infrastructure Audit Only"
    echo "     Complete Azure resource inventory (VMs, storage, networks, etc.)"
    echo ""
    echo "  4) 🎯 All Audits"
    echo "     Complete comprehensive audit (DCR + Security + Infrastructure)"
    echo ""
    echo "  5) ⚙️  Custom Selection"
    echo "     Choose specific combinations"
    echo ""
    echo "  0) Exit"
    echo ""
    echo -n "Select option (0-5): "
}

# Get audit selection
get_audit_selection() {
    while true; do
        show_interactive_menu
        read -r choice
        
        case $choice in
            1)
                AUDIT_DCRS=true
                echo -e "\n${GREEN}✓ DCR Audit selected${NC}"
                break
                ;;
            2)
                AUDIT_RBAC_SECURITY=true
                echo -e "\n${GREEN}✓ Security Audit selected${NC}"
                break
                ;;
            3)
                AUDIT_FULL_INFRASTRUCTURE=true
                echo -e "\n${GREEN}✓ Infrastructure Audit selected${NC}"
                break
                ;;
            4)
                AUDIT_ALL=true
                AUDIT_DCRS=true
                AUDIT_RBAC_SECURITY=true
                AUDIT_FULL_INFRASTRUCTURE=true
                echo -e "\n${GREEN}✓ All Audits selected (DCR + Security + Infrastructure)${NC}"
                break
                ;;
            5)
                echo -e "\n${PURPLE}Custom Selection:${NC}"
                echo -n "Include DCR Audit? (y/N): "
                read -r dcr_choice
                [[ "$dcr_choice" =~ ^[Yy]$ ]] && AUDIT_DCRS=true
                
                echo -n "Include Security Audit? (y/N): "
                read -r sec_choice
                [[ "$sec_choice" =~ ^[Yy]$ ]] && AUDIT_RBAC_SECURITY=true
                
                echo -n "Include Infrastructure Audit? (y/N): "
                read -r infra_choice
                [[ "$infra_choice" =~ ^[Yy]$ ]] && AUDIT_FULL_INFRASTRUCTURE=true
                
                if [[ "$AUDIT_DCRS" == true ]] || [[ "$AUDIT_RBAC_SECURITY" == true ]] || [[ "$AUDIT_FULL_INFRASTRUCTURE" == true ]]; then
                    echo -e "\n${GREEN}✓ Custom selection configured${NC}"
                    break
                else
                    echo -e "\n${RED}❌ No audits selected. Please choose at least one.${NC}"
                    sleep 2
                fi
                ;;
            0)
                echo -e "\n${YELLOW}Exiting...${NC}"
                exit 0
                ;;
            *)
                echo -e "\n${RED}Invalid option. Please try again.${NC}"
                sleep 2
                ;;
        esac
    done
    
    echo ""
    sleep 1
}

# Get subscription and configuration (exactly like original script)
get_configuration() {
    echo ""
    
    # Prompt for subscription ID
    if [[ -z "$SUBSCRIPTION_FILTER" ]]; then
        read -p "Please enter your Azure Subscription ID: " SUBSCRIPTION_FILTER
        
        if [[ -z "$SUBSCRIPTION_FILTER" ]]; then
            error "Subscription ID is required"
        fi
    fi
    
    # Prompt for resource group
    if [[ -z "$RESOURCE_GROUP_FILTER" ]]; then
        read -p "Please enter your Azure Resource Group name: " RESOURCE_GROUP_FILTER
        
        if [[ -z "$RESOURCE_GROUP_FILTER" ]]; then
            error "Resource Group name is required"
        fi
    fi
    
    # Prompt for workspace name
    if [[ -z "$WORKSPACE_NAME_FILTER" ]]; then
        read -p "Please enter your Azure Sentinel Workspace name: " WORKSPACE_NAME_FILTER
        
        if [[ -z "$WORKSPACE_NAME_FILTER" ]]; then
            error "Workspace name is required"
        fi
    fi
    
    echo ""
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dcr-audit)
            AUDIT_DCRS=true
            shift
            ;;
        --security-audit)
            AUDIT_RBAC_SECURITY=true
            shift
            ;;
        --infrastructure-audit)
            AUDIT_FULL_INFRASTRUCTURE=true
            shift
            ;;
        --all)
            AUDIT_ALL=true
            AUDIT_DCRS=true
            AUDIT_RBAC_SECURITY=true
            AUDIT_FULL_INFRASTRUCTURE=true
            shift
            ;;
        -i|--interactive)
            INTERACTIVE_MODE=true
            shift
            ;;
        -s|--subscription)
            SUBSCRIPTION_FILTER="$2"
            shift 2
            ;;
        -r|--resource-group)
            RESOURCE_GROUP_FILTER="$2"
            shift 2
            ;;
        -w|--workspace)
            WORKSPACE_NAME_FILTER="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --no-zip)
            CREATE_ZIP=false
            shift
            ;;
        --no-csv)
            EXPORT_CSV=false
            shift
            ;;
        --list-subs)
            echo "Accessible subscriptions:"
            az account list --all --query "[?state=='Enabled'].{ID:id, Name:name, Tenant:tenantId}" -o table
            exit 0
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Interactive mode
if [[ "$INTERACTIVE_MODE" == true ]]; then
    get_audit_selection
    get_configuration
elif [[ "$AUDIT_DCRS" == false ]] && [[ "$AUDIT_RBAC_SECURITY" == false ]] && [[ "$AUDIT_FULL_INFRASTRUCTURE" == false ]]; then
    # Default behavior - prompt for required variables like original script
    get_configuration
    
    # Default to all audits if none specified
    echo "No specific audit selected - running complete audit"
    AUDIT_ALL=true
    AUDIT_DCRS=true
    AUDIT_RBAC_SECURITY=true
    AUDIT_FULL_INFRASTRUCTURE=true
fi

# Prerequisites check
log "Checking prerequisites..."

if ! command -v az &> /dev/null; then
    error "Azure CLI not installed"
fi

if ! az account show &> /dev/null; then
    error "Not logged in to Azure. Run 'az login' first"
fi

# Install required extensions
log "Installing required Azure CLI extensions..."
extensions=("kusto" "sentinel" "monitor-control-service" "log-analytics")
for ext in "${extensions[@]}"; do
    if ! az extension list --query "[?name=='$ext']" -o tsv &>/dev/null; then
        log "  Installing extension: $ext"
        az extension add --name "$ext" --yes &>/dev/null || warn "Failed to install $ext extension"
    fi
done

# Create output directory
mkdir -p "$OUTPUT_DIR"
log "Output directory: $OUTPUT_DIR"

# Initialize error log
echo "Operation,ResourceType,ErrorMessage,Timestamp" > "$OUTPUT_DIR/error_log.csv"

# Get subscriptions - now focuses on the specified subscription
get_subscriptions_clean() {
    # Always use the specified subscription (required now)
    echo "$SUBSCRIPTION_FILTER"
}

subscriptions_raw=$(get_subscriptions_clean)
if [[ -z "$subscriptions_raw" ]]; then
    error "No accessible subscriptions found"
fi

readarray -t subscriptions <<< "$subscriptions_raw"
log "Found ${#subscriptions[@]} subscription(s) to audit"

# Function to check role assignments and permissions
check_and_output_permissions() {
    local scope="$1"
    local output_file="$2"
    local description="$3"
    
    role_assignment=$(az role assignment list --scope "$scope" --output json 2>&1)
    
    if [[ $? -eq 0 ]]; then
        echo "$role_assignment" | jq -r '.[] | ["\(.roleDefinitionName)", "\(.scope)", "\(.principalType)", "\(.principalName)", "\(.principalId)", "\(.createdOn // \"Unknown\")"] | @csv' >> "$output_file" 2>/dev/null || {
            warn "Failed to parse role assignments for scope: $scope"
        }
    else
        warn "Error checking permissions at scope $scope"
        echo "check_permissions,$scope,\"$role_assignment\",$(date)" >> "$OUTPUT_DIR/error_log.csv"
    fi
}

# Function to safely execute Azure CLI commands
safe_audit_command() {
    local operation="$1"
    local resource_type="$2"
    local command="$3"
    local output_file="$4"
    local jq_filter="$5"
    
    result=$(eval "$command" 2>&1)
    if [[ $? -eq 0 && -n "$result" && "$result" != "[]" ]]; then
        if [[ -n "$jq_filter" ]]; then
            echo "$result" | jq -r "$jq_filter" >> "$output_file" 2>/dev/null || {
                warn "Failed to parse $resource_type data"
                echo "$operation,$resource_type,JSON parsing failed,$(date)" >> "$OUTPUT_DIR/error_log.csv"
            }
        else
            echo "$result" >> "$output_file"
        fi
    else
        if [[ "$result" != "[]" ]]; then
            echo "$operation,$resource_type,$result,$(date)" >> "$OUTPUT_DIR/error_log.csv"
        fi
    fi
}

# Function to validate results
check_for_results() {
    local file="$1"
    line_count=$(wc -l < "$file" 2>/dev/null || echo 0)
    
    if [[ $line_count -le 1 ]]; then
        echo "No results found" >> "$file"
    fi
}

# DCR Audit Function
perform_dcr_audit() {
    local subscription_id=$1
    local sub_name_clean=$2
    
    log "  Performing DCR audit..."
    
    # Get DCRs
    dcr_file="$OUTPUT_DIR/dcrs_${sub_name_clean}_${subscription_id}.json"
    az monitor data-collection rule list --output json > "$dcr_file" 2>/dev/null || {
        warn "Failed to get DCRs for subscription: $subscription_id"
        echo "[]" > "$dcr_file"
        return
    }
    
    dcr_count=$(jq length "$dcr_file")
    
    if [[ $dcr_count -eq 0 ]]; then
        log "    No DCRs found in this subscription"
        return
    fi
    
    log "    Found $dcr_count DCRs"
    
    # Generate DCR report
    report_file="$OUTPUT_DIR/dcr_report_${sub_name_clean}_${subscription_id}.txt"
    {
        echo "=== DATA COLLECTION RULES AUDIT REPORT ==="
        echo "Subscription: $(az account show --query name -o tsv 2>/dev/null) ($subscription_id)"
        echo "Generated: $(date)"
        echo "DCRs Found: $dcr_count"
        echo ""
        
        echo "=== DCR INVENTORY ==="
        jq -r '.[] | "Name: \(.name)\nLocation: \(.location)\nResource Group: \(.resourceGroup)\nKind: \(.kind // "Unknown")\nProvisioning State: \(.properties.provisioningState // "Unknown")\n"' "$dcr_file"
        
        echo "=== DATA SOURCES ANALYSIS ==="
        
        # Performance Counters
        perf_count=$(jq '[.[] | select(.properties.dataSources.performanceCounters // false)] | length' "$dcr_file")
        echo "DCRs with Performance Counters: $perf_count"
        if [[ $perf_count -gt 0 ]]; then
            echo "Performance Counter Examples:"
            jq -r '.[] | select(.properties.dataSources.performanceCounters) | .properties.dataSources.performanceCounters[] | .counterSpecifiers[]' "$dcr_file" | head -5 | sed 's/^/  /'
        fi
        echo ""
        
        # Windows Event Logs
        event_count=$(jq '[.[] | select(.properties.dataSources.windowsEventLogs // false)] | length' "$dcr_file")
        echo "DCRs with Windows Event Logs: $event_count"
        if [[ $event_count -gt 0 ]]; then
            echo "Event Log Examples:"
            jq -r '.[] | select(.properties.dataSources.windowsEventLogs) | .properties.dataSources.windowsEventLogs[] | .xPathQueries[]' "$dcr_file" | head -3 | sed 's/^/  /'
        fi
        echo ""
        
        # Syslog
        syslog_count=$(jq '[.[] | select(.properties.dataSources.syslog // false)] | length' "$dcr_file")
        echo "DCRs with Syslog: $syslog_count"
        if [[ $syslog_count -gt 0 ]]; then
            echo "Syslog Facilities:"
            jq -r '.[] | select(.properties.dataSources.syslog) | .properties.dataSources.syslog[] | .facilityNames[]' "$dcr_file" | sort -u | sed 's/^/  /'
        fi
        echo ""
        
        # Log Files
        logfile_count=$(jq '[.[] | select(.properties.dataSources.logFiles // false)] | length' "$dcr_file")
        echo "DCRs with Custom Log Files: $logfile_count"
        if [[ $logfile_count -gt 0 ]]; then
            echo "Log File Patterns:"
            jq -r '.[] | select(.properties.dataSources.logFiles) | .properties.dataSources.logFiles[] | .filePatterns[]' "$dcr_file" | head -5 | sed 's/^/  /'
        fi
        echo ""
        
        echo "=== COST OPTIMIZATION OPPORTUNITIES ==="
        echo ""
        
        echo "🎯 HIGH VOLUME CANDIDATES (Basic Logs tier):"
        echo "Performance Counter DCRs: $perf_count"
        if [[ $perf_count -gt 0 ]]; then
            echo "  Recommendation: Move to Basic Logs tier for ~80% cost reduction"
            jq -r '.[] | select(.properties.dataSources.performanceCounters) | "  - \(.name) (\(.resourceGroup))"' "$dcr_file"
        fi
        echo ""
        
        echo "🎯 ARCHIVAL CANDIDATES (Storage Account):"
        echo "Custom Log File DCRs: $logfile_count"
        if [[ $logfile_count -gt 0 ]]; then
            echo "  Recommendation: Add dual destination to Storage Account"
            jq -r '.[] | select(.properties.dataSources.logFiles) | "  - \(.name) (\(.resourceGroup))"' "$dcr_file"
        fi
        echo ""
        
        echo "=== DESTINATIONS ==="
        echo "Log Analytics Workspaces:"
        jq -r '.[] | .properties.destinations.logAnalytics[]? | .workspaceResourceId' "$dcr_file" | sed 's/.*\///' | sort -u | sed 's/^/  /'
        
    } > "$report_file"
    
    # CSV export if requested
    if [[ "$EXPORT_CSV" == true ]]; then
        csv_file="$OUTPUT_DIR/dcrs_${sub_name_clean}_${subscription_id}.csv"
        {
            echo "Name,ResourceGroup,Location,Kind,ProvisioningState,HasPerfCounters,HasEventLogs,HasSyslog,HasLogFiles,LogAnalyticsWorkspaces"
            jq -r '.[] | [
                .name,
                .resourceGroup,
                .location,
                (.kind // "Unknown"),
                (.properties.provisioningState // "Unknown"),
                (if .properties.dataSources.performanceCounters then "Yes" else "No" end),
                (if .properties.dataSources.windowsEventLogs then "Yes" else "No" end),
                (if .properties.dataSources.syslog then "Yes" else "No" end),
                (if .properties.dataSources.logFiles then "Yes" else "No" end),
                ((.properties.destinations.logAnalytics[]?.workspaceResourceId // "") | split("/")[-1])
            ] | @csv' "$dcr_file"
        } > "$csv_file"
    fi
    
    log "    DCR audit completed"
}

# Security Audit Function
perform_security_audit() {
    local subscription_id=$1
    local sub_name_clean=$2
    security_dir="$OUTPUT_DIR/security_audit_${sub_name_clean}_${subscription_id}"
    
    log "  Performing security audit..."
    mkdir -p "$security_dir"
    
    # Define security audit files
    declare -A security_files=(
        ["roles"]="$security_dir/roles_audit.csv"
        ["rbac_analysis"]="$security_dir/rbac_analysis.csv"
        ["custom_roles"]="$security_dir/custom_roles.csv"
        ["service_principals"]="$security_dir/service_principals.csv"
        ["managed_identities"]="$security_dir/managed_identities.csv"
        ["defender_alerts"]="$security_dir/defender_alerts.csv"
        ["defender_recommendations"]="$security_dir/defender_recommendations.csv"
        ["defender_settings"]="$security_dir/defender_settings.csv"
        ["security_contacts"]="$security_dir/security_contacts.csv"
    )
    
    declare -A security_headers=(
        ["roles"]="Scope,RoleName,PrincipalType,PrincipalName,PrincipalId,CreatedDate"
        ["rbac_analysis"]="PrincipalName,PrincipalType,RoleCount,HighPrivilegeRoles,Scopes,RiskLevel"
        ["custom_roles"]="RoleName,Description,Actions,NotActions,Scopes,CreatedDate"
        ["service_principals"]="DisplayName,AppId,ObjectId,ServicePrincipalType,AccountEnabled,KeyCredentials,PasswordCredentials"
        ["managed_identities"]="Name,Type,ResourceGroup,AssociatedResource,ClientId,PrincipalId"
        ["defender_alerts"]="AlertName,Severity,Status,ResourceType,ResourceName,Description,StartTimeUtc,Tactics"
        ["defender_recommendations"]="RecommendationName,Severity,State,ResourceType,ResourceName,Description,Category"
        ["defender_settings"]="SettingKind,Name,Enabled,Properties"
        ["security_contacts"]="Email,Phone,AlertNotifications,AlertsToAdmins,NotificationsByRole"
    )
    
    # Create CSV headers
    for key in "${!security_files[@]}"; do
        echo "${security_headers[$key]}" > "${security_files[$key]}"
    done
    
    # Subscription-level role assignments
    log "    Auditing RBAC..."
    safe_audit_command "subscription_roles" "Roles" \
        "az role assignment list --scope '/subscriptions/$subscription_id' --include-inherited --output json" \
        "${security_files["roles"]}" \
        '.[] | ["/subscriptions/'$subscription_id'", .roleDefinitionName, .principalType, (.principalName // "Unknown"), (.principalId // "Unknown"), (.createdOn // "Unknown")] | @csv'
    
    # RBAC Analysis
    all_roles_temp=$(mktemp)
    az role assignment list --scope "/subscriptions/$subscription_id" --include-inherited --output json > "$all_roles_temp" 2>/dev/null || echo "[]" > "$all_roles_temp"
    
    {
        echo "PrincipalName,PrincipalType,RoleCount,HighPrivilegeRoles,Scopes,RiskLevel"
        jq -r '
        group_by(.principalId) | 
        .[] |
        {
            principalName: (.[0].principalName // "Unknown"),
            principalType: .[0].principalType,
            roleCount: length,
            roles: [.[].roleDefinitionName] | unique,
            scopes: [.[].scope] | unique
        } |
        .highPrivilegeRoles = (.roles | map(select(. as $role | ["Owner","Contributor","User Access Administrator","Security Admin","Global Administrator","Privileged Role Administrator"] | index($role) != null))) |
        .riskLevel = (
            if (.highPrivilegeRoles | length) > 2 then "HIGH"
            elif (.highPrivilegeRoles | length) > 0 then "MEDIUM" 
            else "LOW" end
        ) |
        [.principalName, .principalType, .roleCount, (.highPrivilegeRoles | join(";")), (.scopes | join(";")), .riskLevel] | @csv
        ' "$all_roles_temp"
    } > "${security_files["rbac_analysis"]}"
    
    rm -f "$all_roles_temp"
    
    # Custom Roles
    safe_audit_command "custom_roles" "Custom Roles" \
        "az role definition list --custom-role-only --output json" \
        "${security_files["custom_roles"]}" \
        '.[] | [.roleName, (.description // "No description"), (.permissions[0].actions // [] | join(";")), (.permissions[0].notActions // [] | join(";")), (.assignableScopes | join(";")), (.createdOn // "Unknown")] | @csv'
    
    # Service Principals
    safe_audit_command "service_principals" "Service Principals" \
        "az ad sp list --all --output json" \
        "${security_files["service_principals"]}" \
        '.[] | [(.displayName // "Unknown"), (.appId // "Unknown"), .id, (.servicePrincipalType // "Unknown"), .accountEnabled, (.keyCredentials | length), (.passwordCredentials | length)] | @csv'
    
    # Managed Identities
    safe_audit_command "managed_identities" "Managed Identities" \
        "az identity list --output json" \
        "${security_files["managed_identities"]}" \
        '.[] | [.name, .type, .resourceGroup, (.tags.associatedResource // "Unknown"), .clientId, .principalId] | @csv'
    
    # Microsoft Defender
    log "    Auditing Microsoft Defender..."
    
    # Defender Alerts - handle potential permission issues
    safe_audit_command "defender_alerts" "Defender Alerts" \
        "az security alert list --output json 2>/dev/null || echo '[]'" \
        "${security_files["defender_alerts"]}" \
        '.[] | [(.alertDisplayName // .productName // "Unknown"), (.reportedSeverity // "Unknown"), (.state // "Unknown"), (.compromisedEntity // "Unknown"), (.resourceIdentifiers[0].resourceName // "Unknown"), (.description // "No description"), (.startTimeUtc // "Unknown"), ((.tactics // []) | join(";"))] | @csv'
    
    # Security Recommendations - more robust error handling
    safe_audit_command "defender_recommendations" "Security Recommendations" \
        "az security assessment list --output json 2>/dev/null || echo '[]'" \
        "${security_files["defender_recommendations"]}" \
        '.[] | [(.displayName // "Unknown"), (.metadata.severity // "Unknown"), (.status.code // "Unknown"), (.resourceDetails.resourceType // "Unknown"), (.resourceDetails.resourceName // "Unknown"), (.metadata.description // "No description"), (.metadata.category // "Unknown")] | @csv'
    
    # Defender Settings - handle different response formats
    safe_audit_command "defender_settings" "Defender Settings" \
        "az security setting list --output json 2>/dev/null || echo '[]'" \
        "${security_files["defender_settings"]}" \
        '.[] | [(.kind // "Unknown"), (.name // "Unknown"), (.enabled // false), ((.properties // {}) | tostring)] | @csv'
    
    # Security Contacts - handle empty responses better
    safe_audit_command "security_contacts" "Security Contacts" \
        "az security contact list --output json 2>/dev/null || echo '[]'" \
        "${security_files["security_contacts"]}" \
        '.[] | [(.email // "Not configured"), (.phone // "Not configured"), (.alertNotifications // "Unknown"), (.alertsToAdmins // "Unknown"), (.notificationsByRole // "Unknown")] | @csv'
    
    # Validate results
    for key in "${!security_files[@]}"; do
        check_for_results "${security_files[$key]}"
    done
    
    # Generate security report
    generate_security_report "$security_dir" "$subscription_id"
    
    log "    Security audit completed"
}

# Generate security report
generate_security_report() {
    local security_dir=$1
    local subscription_id=$2
    security_report="$security_dir/SECURITY_REPORT.txt"
    
    {
        echo "=========================================="
        echo "🔐 AZURE SECURITY & RBAC AUDIT REPORT"
        echo "=========================================="
        echo "Subscription: $subscription_id"
        echo "Generated: $(date)"
        echo ""
        
        echo "🚨 CRITICAL SECURITY FINDINGS"
        echo "=========================================="
        
        # High Risk RBAC Principals
        if [[ -f "$security_dir/rbac_analysis.csv" ]]; then
            echo ""
            echo "🔴 HIGH RISK RBAC PRINCIPALS:"
            high_risk_found=false
            while IFS=, read -r principal_name principal_type role_count high_priv_roles scopes risk_level; do
                if [[ "$risk_level" == "HIGH" ]]; then
                    echo "  ❌ $principal_name ($principal_type)"
                    echo "     Roles: $role_count | High-Privilege: $high_priv_roles"
                    high_risk_found=true
                fi
            done < <(tail -n +2 "$security_dir/rbac_analysis.csv")
            
            if [[ "$high_risk_found" == false ]]; then
                echo "  ✅ No high-risk RBAC principals found"
            fi
        fi
        
        # Statistics
        total_roles=$(($(wc -l < "$security_dir/roles_audit.csv") - 1))
        [[ $total_roles -lt 0 ]] && total_roles=0
        
        if [[ -f "$security_dir/rbac_analysis.csv" ]]; then
            total_high_risk=$(awk -F, '$6=="HIGH" {count++} END {print count+0}' "$security_dir/rbac_analysis.csv")
        else
            total_high_risk=0
        fi
        
        echo ""
        echo "📊 SECURITY SUMMARY"
        echo "=========================================="
        echo "🔑 RBAC Statistics:"
        echo "    Total Role Assignments: $total_roles"
        echo "    High-Risk Principals: $total_high_risk"
        echo ""
        
        # Risk Assessment
        overall_risk="LOW"
        if [[ $total_high_risk -gt 0 ]]; then
            overall_risk="HIGH"
        fi
        
        echo "🎯 OVERALL SECURITY RISK LEVEL: $overall_risk"
        echo ""
        
        case $overall_risk in
            "HIGH")
                echo "❌ CRITICAL: Immediate attention required"
                ;;
            "MEDIUM")
                echo "⚠️  MODERATE: Review and improve security posture"
                ;;
            "LOW")
                echo "✅ GOOD: Maintain current security practices"
                ;;
        esac
        echo ""
        
        echo "📈 RECOMMENDATIONS:"
        echo "  1. Review all HIGH risk RBAC principals"
        echo "  2. Investigate high-severity Defender alerts"
        echo "  3. Implement principle of least privilege"
        echo "  4. Regular access reviews (quarterly)"
        echo "  5. Enable all Defender plans"
        echo ""
        
        echo "Report generated: $(date)"
        
    } > "$security_report"
}

# Infrastructure Audit Function  
perform_infrastructure_audit() {
    local subscription_id=$1
    local sub_name_clean=$2
    infra_dir="$OUTPUT_DIR/infrastructure_audit_${sub_name_clean}_${subscription_id}"
    
    log "  Performing infrastructure audit..."
    mkdir -p "$infra_dir"
    
    # Define infrastructure audit files
    declare -A infra_files=(
        ["sentinel_data_connectors"]="$infra_dir/sentinel_data_connectors.csv"
        ["sentinel_incidents"]="$infra_dir/sentinel_incidents.csv" 
        ["sentinel_analytics_rules"]="$infra_dir/sentinel_analytics_rules.csv"
        ["storage_accounts"]="$infra_dir/storage_accounts.csv"
        ["vms"]="$infra_dir/vms.csv"
        ["vnets"]="$infra_dir/vnets.csv"
        ["function_apps"]="$infra_dir/function_apps.csv"
        ["logic_apps"]="$infra_dir/logic_apps.csv"
        ["key_vaults"]="$infra_dir/key_vaults.csv"
        ["sql_databases"]="$infra_dir/sql_databases.csv"
        ["cosmos_dbs"]="$infra_dir/cosmos_dbs.csv"
        ["aks_clusters"]="$infra_dir/aks_clusters.csv"
        ["adx_clusters"]="$infra_dir/adx_clusters.csv"
        ["app_registrations"]="$infra_dir/app_registrations.csv"
    )
    
    declare -A infra_headers=(
        ["sentinel_data_connectors"]="WorkspaceName,DataConnectorName,Kind,State"
        ["sentinel_incidents"]="WorkspaceName,IncidentNumber,Title,Status,Severity,CreatedTime"
        ["sentinel_analytics_rules"]="WorkspaceName,RuleName,DisplayName,Enabled,Severity,Kind"
        ["storage_accounts"]="Name,ResourceGroup,Location,Kind,AccessTier,EncryptionStatus"
        ["vms"]="Name,ResourceGroup,Location,Size,PowerState,PrivateIP,PublicIP"
        ["vnets"]="Name,ResourceGroup,Location,AddressSpace,SubnetCount"
        ["function_apps"]="Name,ResourceGroup,Location,State,Runtime"
        ["logic_apps"]="Name,ResourceGroup,Location,State,Kind"
        ["key_vaults"]="Name,ResourceGroup,Location,VaultUri,EnabledForDeployment"
        ["sql_databases"]="ServerName,DatabaseName,ResourceGroup,Location,Status,Edition"
        ["cosmos_dbs"]="Name,ResourceGroup,Location,Kind,DocumentEndpoint"
        ["aks_clusters"]="Name,ResourceGroup,Location,KubernetesVersion,NodeCount,PowerState"
        ["adx_clusters"]="Name,ResourceGroup,Location,State,Uri"
        ["app_registrations"]="DisplayName,AppId,ObjectId,CreatedDateTime"
    )
    
    # Create CSV headers
    for key in "${!infra_files[@]}"; do
        echo "${infra_headers[$key]}" > "${infra_files[$key]}"
    done
    
    # Get resource groups - now focuses on the specified resource group
    resource_groups="$RESOURCE_GROUP_FILTER"
    
    if [[ -z "$resource_groups" ]]; then
        warn "No resource groups accessible in subscription: $subscription_id"
        return
    fi
    
    # Process each resource group
    while IFS= read -r rg; do
        [[ -z "$rg" ]] && continue
        log "    Processing resource group: $rg"
        
        # Storage Accounts
        safe_audit_command "storage" "Storage Accounts" \
            "az storage account list --resource-group '$rg' --output json" \
            "${infra_files["storage_accounts"]}" \
            '.[] | [.name, .resourceGroup, .location, .kind, (.accessTier // "N/A"), (.encryption.services.blob.enabled // "Unknown")] | @csv'
        
        # Virtual Machines
        safe_audit_command "vms" "Virtual Machines" \
            "az vm list --resource-group '$rg' --show-details --output json" \
            "${infra_files["vms"]}" \
            '.[] | [.name, .resourceGroup, .location, .hardwareProfile.vmSize, .powerState, (.privateIps // ""), (.publicIps // "")] | @csv'
        
        # Virtual Networks
        safe_audit_command "vnets" "Virtual Networks" \
            "az network vnet list --resource-group '$rg' --output json" \
            "${infra_files["vnets"]}" \
            '.[] | [.name, .resourceGroup, .location, (.addressSpace.addressPrefixes | join(";")), (.subnets | length)] | @csv'
        
        # Function Apps
        safe_audit_command "function_apps" "Function Apps" \
            "az functionapp list --resource-group '$rg' --output json" \
            "${infra_files["function_apps"]}" \
            '.[] | [.name, .resourceGroup, .location, .state, (.siteConfig.linuxFxVersion // .siteConfig.windowsFxVersion // "Unknown")] | @csv'
        
        # Logic Apps
        safe_audit_command "logic_apps" "Logic Apps" \
            "az logic workflow list --resource-group '$rg' --output json" \
            "${infra_files["logic_apps"]}" \
            '.[] | [.name, .resourceGroup, .location, .state, (.kind // "Unknown")] | @csv'
        
        # Key Vaults
        safe_audit_command "key_vaults" "Key Vaults" \
            "az keyvault list --resource-group '$rg' --output json" \
            "${infra_files["key_vaults"]}" \
            '.[] | [.name, .resourceGroup, .location, .properties.vaultUri, .properties.enabledForDeployment] | @csv'
        
        # AKS Clusters
        safe_audit_command "aks" "AKS Clusters" \
            "az aks list --resource-group '$rg' --output json" \
            "${infra_files["aks_clusters"]}" \
            '.[] | [.name, .resourceGroup, .location, .kubernetesVersion, .agentPoolProfiles[0].count, (.powerState.code // "Unknown")] | @csv'
        
        # Cosmos DB
        safe_audit_command "cosmos" "Cosmos DB" \
            "az cosmosdb list --resource-group '$rg' --output json" \
            "${infra_files["cosmos_dbs"]}" \
            '.[] | [.name, .resourceGroup, .location, .kind, .documentEndpoint] | @csv'
        
        # Azure Data Explorer
        safe_audit_command "adx" "ADX Clusters" \
            "az kusto cluster list --resource-group '$rg' --output json" \
            "${infra_files["adx_clusters"]}" \
            '.[] | [.name, .resourceGroup, .location, .state, (.uri // "Unknown")] | @csv'
        
        # SQL Databases
        sql_servers=$(az sql server list --resource-group "$rg" --query "[].name" -o tsv 2>/dev/null)
        if [[ -n "$sql_servers" ]]; then
            while IFS= read -r server; do
                [[ -z "$server" ]] && continue
                safe_audit_command "sql_dbs" "SQL Databases" \
                    "az sql db list --resource-group '$rg' --server '$server' --output json" \
                    "${infra_files["sql_databases"]}" \
                    '.[] | ["'$server'", .name, .resourceGroup, .location, .status, (.edition // "Unknown")] | @csv'
            done <<< "$sql_servers"
        fi
        
        # Sentinel (focus on the specified workspace)
        workspaces="$WORKSPACE_NAME_FILTER"
        
        if [[ -n "$workspaces" ]]; then
            while IFS= read -r workspace; do
                [[ -z "$workspace" ]] && continue
                
                if az sentinel data-connector list --resource-group "$rg" --workspace-name "$workspace" --output json &>/dev/null; then
                    log "      Found Sentinel workspace: $workspace"
                    
                    safe_audit_command "sentinel_connectors" "Sentinel Data Connectors" \
                        "az sentinel data-connector list --resource-group '$rg' --workspace-name '$workspace' --output json" \
                        "${infra_files["sentinel_data_connectors"]}" \
                        '.[] | ["'$workspace'", .name, .kind, (.properties.dataTypes[0].state // "Unknown")] | @csv'
                    
                    safe_audit_command "sentinel_incidents" "Sentinel Incidents" \
                        "az sentinel incident list --resource-group '$rg' --workspace-name '$workspace' --output json" \
                        "${infra_files["sentinel_incidents"]}" \
                        '.[] | ["'$workspace'", (.properties.incidentNumber // "Unknown"), .properties.title, .properties.status, .properties.severity, .properties.createdTimeUtc] | @csv'
                    
                    safe_audit_command "sentinel_rules" "Sentinel Analytics Rules" \
                        "az sentinel alert-rule list --resource-group '$rg' --workspace-name '$workspace' --output json" \
                        "${infra_files["sentinel_analytics_rules"]}" \
                        '.[] | ["'$workspace'", .name, (.properties.displayName // "Unknown"), .properties.enabled, (.properties.severity // "Unknown"), (.kind // "Unknown")] | @csv'
                fi
            done <<< "$workspaces"
        fi
        
    done <<< "$resource_groups"
    
    # App Registrations (subscription level)
    safe_audit_command "app_registrations" "App Registrations" \
        "az ad app list --output json" \
        "${infra_files["app_registrations"]}" \
        '.[] | [.displayName, .appId, .id, (.createdDateTime // "Unknown")] | @csv'
    
    # Validate results
    for key in "${!infra_files[@]}"; do
        check_for_results "${infra_files[$key]}"
    done
    
    # Generate summary
    generate_infrastructure_summary "$infra_dir" "$subscription_id"
    
    log "    Infrastructure audit completed"
}

# Generate infrastructure summary
generate_infrastructure_summary() {
    local infra_dir=$1
    local subscription_id=$2
    summary_file="$infra_dir/infrastructure_summary.txt"
    
    {
        echo "=== AZURE INFRASTRUCTURE AUDIT SUMMARY ==="
        echo "Subscription: $subscription_id"
        echo "Generated: $(date)"
        echo ""
        
        echo "📊 RESOURCE COUNTS:"
        total_resources=0
        
        # Count resources in each category
        for csv_file in "$infra_dir"/*.csv; do
            if [[ -f "$csv_file" ]]; then
                filename=$(basename "$csv_file" .csv)
                count=$(($(wc -l < "$csv_file") - 1))
                [[ $count -lt 0 ]] && count=0
                
                if [[ $count -gt 0 && "$filename" != "error_log" ]]; then
                    printf "  %-25s: %d\n" "${filename//_/ }" "$count"
                    total_resources=$((total_resources + count))
                fi
            fi
        done
        
        echo ""
        echo "Total Resources Audited: $total_resources"
        echo ""
        
        echo "Report generated: $(date)"
        
    } > "$summary_file"
}

# Main execution loop
log "Starting Azure audit..."

for subscription_id in "${subscriptions[@]}"; do
    [[ -z "$subscription_id" ]] && continue
    
    log "Processing subscription: $subscription_id"
    
    # Set subscription context
    if ! az account set --subscription "$subscription_id" 2>/dev/null; then
        warn "Cannot access subscription: $subscription_id"
        continue
    fi
    
    # Get subscription info
    sub_info=$(az account show --query "{name:name, tenantId:tenantId}" -o json 2>/dev/null)
    sub_name=$(echo "$sub_info" | jq -r '.name // "Unknown"')
    tenant_id=$(echo "$sub_info" | jq -r '.tenantId // "Unknown"')
    sub_name_clean=$(echo "$sub_name" | sed 's/[^a-zA-Z0-9_-]/_/g')
    
    info "  Subscription: $sub_name"
    info "  Tenant: $tenant_id"
    
    # Perform selected audits
    if [[ "$AUDIT_DCRS" == true ]]; then
        perform_dcr_audit "$subscription_id" "$sub_name_clean"
    fi
    
    if [[ "$AUDIT_RBAC_SECURITY" == true ]]; then
        perform_security_audit "$subscription_id" "$sub_name_clean"
    fi
    
    if [[ "$AUDIT_FULL_INFRASTRUCTURE" == true ]]; then
        perform_infrastructure_audit "$subscription_id" "$sub_name_clean"
    fi
    
    log "Completed subscription: $subscription_id"
    echo ""
done

# Generate final summary
{
    echo "=== AZURE AUDIT COMPLETE ==="
    echo "Generated: $(date)"
    echo "Output Directory: $OUTPUT_DIR"
    echo ""
    
    echo "AUDIT COMPONENTS EXECUTED:"
    echo "  DCR Audit: $([ "$AUDIT_DCRS" == true ] && echo "✓" || echo "✗")"
    echo "  Security Audit: $([ "$AUDIT_RBAC_SECURITY" == true ] && echo "✓" || echo "✗")"
    echo "  Infrastructure Audit: $([ "$AUDIT_FULL_INFRASTRUCTURE" == true ] && echo "✓" || echo "✗")"
    echo ""
    
    echo "SUBSCRIPTIONS PROCESSED:"
    for subscription_id in "${subscriptions[@]}"; do
        [[ -z "$subscription_id" ]] && continue
        az account set --subscription "$subscription_id" 2>/dev/null || continue
        sub_name_summary=$(az account show --query "name" -o tsv 2>/dev/null || echo "Unknown")
        echo "  $sub_name_summary ($subscription_id)"
    done
    echo ""
    
    echo "FILES GENERATED:"
    find "$OUTPUT_DIR" -type f | sort | sed 's/^/  /'
    echo ""
    
    echo "KEY REPORTS TO REVIEW:"
    if [[ "$AUDIT_DCRS" == true ]]; then
        echo "  🔍 DCR Reports: dcr_report_*.txt"
    fi
    if [[ "$AUDIT_RBAC_SECURITY" == true ]]; then
        echo "  🔐 Security Reports: */SECURITY_REPORT.txt"
    fi
    if [[ "$AUDIT_FULL_INFRASTRUCTURE" == true ]]; then
        echo "  🏗️ Infrastructure Summaries: */infrastructure_summary.txt"
    fi
    
} > "$OUTPUT_DIR/AUDIT_COMPLETE.txt"

# Create ZIP file if requested
if [[ "$CREATE_ZIP" == true ]]; then
    log "Creating audit archive..."
    cd "$OUTPUT_DIR" || exit 1
    
    zip_filename="azure_comprehensive_audit_$(date +%Y%m%d_%H%M%S).zip"
    zip -r "$zip_filename" . -x "*.zip" &>/dev/null
    
    cd - >/dev/null
    
    log "Archive created: $OUTPUT_DIR/$zip_filename"
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}    AZURE AUDIT COMPLETED SUCCESSFULLY${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${BLUE}📁 Results Directory: ${NC}$OUTPUT_DIR"
echo -e "${BLUE}📋 Summary Report: ${NC}$OUTPUT_DIR/AUDIT_COMPLETE.txt"
if [[ "$CREATE_ZIP" == true ]]; then
    echo -e "${BLUE}📦 Archive: ${NC}$OUTPUT_DIR/azure_comprehensive_audit_*.zip"
fi
echo ""
echo -e "${PURPLE}Next Steps:${NC}"
echo "  1. Review the AUDIT_COMPLETE.txt for overview"
if [[ "$AUDIT_RBAC_SECURITY" == true ]]; then
    echo "  2. Check SECURITY_REPORT.txt for critical security findings"
fi
if [[ "$AUDIT_DCRS" == true ]]; then
    echo "  3. Review DCR reports for cost optimization opportunities"
fi
if [[ "$AUDIT_FULL_INFRASTRUCTURE" == true ]]; then
    echo "  4. Examine infrastructure summaries for resource inventory"
fi
echo "  5. Import CSV files into Excel/Power BI for detailed analysis"
echo ""

log "Audit completed successfully!"
