#!/usr/bin/env python3

import json, sys, argparse, requests, msal, platform, ctypes
from datetime import datetime, timedelta

# Misc Constant GUIDs
AAD_PREMIUM_P2 = "eec0eb4f-6444-4f95-aba0-50c24d67f998"
AAD_PREMIUM_P1 = "41781fb2-bc02-4b7c-bd55-b576c07bb09d"
GROUP_UNIFIED_TEMPLATE_ID = "62375ab9-6b52-47ed-826b-58e47e0e304b"
GUEST_ROLE_USER = "a0b1b346-4d3e-4e8b-98f8-753987be4970" # https://learn.microsoft.com/en-us/graph/api/resources/authorizationpolicy?view=graph-rest-1.0&preserve-view=true
GUEST_ROLE_GUEST = "10dae51f-b6af-4016-8d66-8c2a99b929b3"
GUEST_ROLE_RESTRICTED = "2af84b1e-32c8-42b7-82bc-daa82404023b"
MICROSOFT_SERVICE_TENANT_ID = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"

# Authentication GUIDs and constants
AUTHORITY_URL = "https://login.microsoftonline.com/"
SCOPE_MS_GRAPH = ["https://graph.microsoft.com/.default"]
SCOPE_AAD_GRAPH = ["https://graph.windows.net/.default"]
SCOPE_ARM = ["https://management.core.windows.net/.default"]
SCOPE_MSPIM = ["01fc33a7-78ba-4d2f-a4b7-768e336e890e/.default"]
OFFICE_CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
AZURECLI_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
POWER_AUTOMATE_CLIENT_ID = "386ce8c0-7421-48c9-a1df-2a532400339f" # not foci
# FOCI clients see https://github.com/dirkjanm/family-of-client-ids-research/blob/main/known-foci-clients.csv

# Could use an enum class for this? maybe refactor in the future
DEVICE_CODE_FLOW="DEVICE_CODE_FLOW"
ROPC_FLOW="ROPC_FLOW"
REFRESH_TOKEN_FLOW="REFRESH_TOKEN_FLOW"

# Default User-Agent Edge on Windows 10
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.2277.112"

# Constant API URLs
AAD_GRAPH_API = "https://graph.windows.net"
MS_GRAPH_API = "https://graph.microsoft.com"
AZURE_PORTAL = "https://portal.azure.com"
ARM_API = "https://management.azure.com"

# Set colors
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[0;33m"
CYAN = "\033[0;36m"
ORANGE = "\033[38;5;208m"
NC = "\033[0m"  # No Color

def unset_colors():
    global RED, GREEN, YELLOW, CYAN, ORANGE, NC
    RED = GREEN = YELLOW = CYAN = ORANGE = NC = ""

if platform.system() == 'Windows':
    IS_WINDOWS = True
else:
    IS_WINDOWS = False

args = None
log_content = ""
json_content = {"findings":[]}

# Start global session for msal and python-requests
# Need to patch the prepare_request method to remove the x-client-os header that msal sets
class PatchedSession(requests.Session):
    def prepare_request(self, request, *args, **kwargs):
        # Call the parent class's prepare_request method
        request = super().prepare_request(request, *args, **kwargs)
        
        # Remove the unwanted header if it exists
        if "x-client-os" in request.headers:
            del request.headers["x-client-os"]
        
        return request

session = PatchedSession()
session.headers.update({"User-Agent": DEFAULT_USER_AGENT})

query_session = requests.session()
query_session.headers = {'User-Agent': DEFAULT_USER_AGENT}


def print_info(text):
    line = f"{CYAN}[+]{NC} {text}"
    print(line)
    global log_content
    if (args and args.output_text):
        log_content += line + "\n"

def print_error(text):
    line = f"{RED}[-]{NC} {text}"
    print(line)
    global log_content
    if (args and args.output_text):
        log_content += line + "\n"

def print_low(text):
    line = f"{YELLOW}[L]{NC} {text}"
    print(line)
    global log_content
    global json_content
    if (args and args.output_text):
        log_content += line + "\n"
    if (args and args.output_json):
        json_content["findings"].append({"criticality": "low","description": text})

def print_med(text):
    line = f"{ORANGE}[M]{NC} {text}"
    print(line)
    global log_content
    global json_content
    if (args and args.output_text):
        log_content += line + "\n"
    if (args and args.output_json):
        json_content["findings"].append({"criticality": "medium","description": text})

def print_high(text):
    line = f"{RED}[H]{NC} {text}"
    print(line)
    global log_content
    global json_content
    if (args and args.output_text):
        log_content += line + "\n"
    if (args and args.output_json):
        json_content["findings"].append({"criticality": "high","description": text})

def print_link(text):
    line = f"{CYAN}[+] {text}{NC}"
    print(line)
    global log_content
    if (args and args.output_text):
        log_content += line + "\n"

def print_simple(text):
    print(text)
    global log_content
    if (args and args.output_text):
        log_content += text + "\n"

def print_header(text):
    print_simple("\n" + "#" * 49)
    print_simple(f"# {text}")
    print_simple("#" * 49 + "\n")

def authenticate_with_msal(client_id, scopes, flow, username=None, password=None, refresh_token = None):
    authority = AUTHORITY_URL + "common"
    if args.tenant_id != None:
        authority = AUTHORITY_URL + args.tenant_id

    # Initialize PublicClientApplication
    app = msal.PublicClientApplication(
        client_id=client_id,
        authority=authority,
        http_client=session
    )

    if flow == DEVICE_CODE_FLOW:
        # Start the device code flow
        flow = app.initiate_device_flow(scopes=scopes)

        # Print message to the user
        print_info(flow['message'])

        # Acquire token using device code
        result = app.acquire_token_by_device_flow(flow)
    elif flow == ROPC_FLOW and username != None and password != None:
        result = app.acquire_token_by_username_password(username, password, scopes=SCOPE_MS_GRAPH)
    elif flow == REFRESH_TOKEN_FLOW and refresh_token != None:
        result = app.acquire_token_by_refresh_token(scopes=scopes, refresh_token=refresh_token)
    else:
        print_error("Can not authenticate with the passed arguments")
        return

    # Check if the token was successfully acquired
    if 'access_token' in result:
        #print_info(f"Got access token for resource {scopes} with client ID {client_id}")
        return result
    else:
        print_error(result.get('error'))
        print_error(result.get('error_description'))
        return

def get_msgraph(endpoint, params, token, version="v1.0"):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    url = MS_GRAPH_API + "/" + version + endpoint
    r = query_session.get(url, params=params, headers=headers)
    result = json.loads(r.text)
    
    # Check request worked
    if "@odata.context" not in result:
        print_error(f"Could not fetch URL: {r.url}")
        print(result)
        return

    return result

def get_msgraph_value(endpoint, params, token, version="v1.0"):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    url = MS_GRAPH_API + "/" + version + endpoint
    results = []
    while True:
        r = query_session.get(url, params=params, headers=headers)
        rawResult = json.loads(r.text)
        
        # Check request worked
        if "@odata.context" not in rawResult:
            print_error(f"Could not fetch URL: {r.url}")
            print(rawResult)
            return
        
        # Add results
        results.extend(rawResult["value"])

        # If no nextLink present, break and return
        if "@odata.nextLink" not in rawResult:
            break
        else:
            url = rawResult["@odata.nextLink"]
            params = {} # nextLink includes the search params

    return results

def get_aadgraph(endpoint, params, tenantId, token, apiVersion = "1.61-internal"):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    url = f"{AAD_GRAPH_API}/{tenantId}{endpoint}"
    params["api-version"] = apiVersion
    r = query_session.get(url, params=params, headers=headers)
    result = json.loads(r.text)
    
    # Check request worked
    if "odata.metadata" not in result:            
        print_error(f"Could not fetch URL: {r.url}")
        print(result)
        return

    return result

def get_aadgraph_value(endpoint, params, tenantId, token, apiVersion = "1.61-internal"):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    url = f"{AAD_GRAPH_API}/{tenantId}{endpoint}"
    results = []
    params["api-version"] = apiVersion
    while True:
        r = query_session.get(url, params=params, headers=headers)
        rawResult = json.loads(r.text)
        
        # Check request worked
        if "odata.metadata" not in rawResult:            
            print_error(f"Could not fetch URL: {r.url}")
            print(rawResult)
            return
        
        # Add results
        results.extend(rawResult["value"])

        # If no nextLink present, break and return
        if "odata.nextLink" not in rawResult:
            break
        else:
            nextLink = rawResult["odata.nextLink"]
            url = f"{AAD_GRAPH_API}/{tenantId}/{nextLink}&api-version={apiVersion}"
            params = {} # nextLink includes the search params

    return results

def get_arm(endpoint, params, token, apiVersion = "2018-02-01"):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    url = ARM_API + endpoint
    params["api-version"] = apiVersion
    r = query_session.get(url, params=params, headers=headers)
    result = json.loads(r.text)

    if "value" not in result:
        print_error(f"Could not fetch URL: {r.url}")
        print(result)
        return

    return result

def basic_info(org, groups, servicePrincipals, groupSettings, users, userRegistrationDetails, msGraphToken, msGraphTokenForAzCli, armToken):
    
    tenantId = org["id"]
    # Object quota
    objNum = org["directorySizeQuota"]["used"]
    objLimit = org["directorySizeQuota"]["total"]
    displayName = org["displayName"]
    onPremisesSyncEnabled = org["onPremisesSyncEnabled"]
    if onPremisesSyncEnabled is None:
        onPremisesSyncEnabled = "Disabled"
    else:
        onPremisesSyncEnabled = "Enabled"

    # Licenses
    aadLicenses = [plan["servicePlanId"] for plan in org["assignedPlans"] if plan["capabilityStatus"] == "Enabled" and plan["service"] == "AADPremiumService"]
    if AAD_PREMIUM_P2 in aadLicenses:
        aadPlan = "Microsoft Entra ID P2"
    elif AAD_PREMIUM_P1 in aadLicenses:
        aadPlan = "Microsoft Entra ID P1"
    else:
        aadPlan = "Microsoft Entra ID Free"

    if users != None:
        userNum = len(users)
        guestNum = len([user for user in users if user["userType"] == "Guest"])
        guestPercent = round(guestNum / userNum * 100, 2)        
        pendingInvitations = get_msgraph_value(
            "/users/",
            {
                "$select":"userPrincipalName,externalUserState,createdDateTime",
                "$filter":"externalUserState eq 'PendingAcceptance'"
            },
            msGraphToken
        )
        pendingInvitationsNum = len(pendingInvitations)
        # Calculate # of orphaned Accounts
        current_datetime = datetime.utcnow() # get the current datetime in UTC timezone        
        invitationsSinceLarger90 = 0
        invitationsSinceLarger180 = 0
        invitationsSinceLarger365 = 0
        for invitation in pendingInvitations:
            date_string = invitation["createdDateTime"] # format '2023-04-25T07:36:44Z'
            given_datetime = datetime.fromisoformat(date_string[:-1]) # convert the input string to a datetime object
            days_since = (current_datetime - given_datetime).days # calculate the number of days between the given datetime and the current datetime
            if days_since > 365:
                invitationsSinceLarger365 += 1
                invitationsSinceLarger180 += 1
                invitationsSinceLarger90 += 1
                continue
            if days_since > 180:
                invitationsSinceLarger180 += 1
                invitationsSinceLarger90 += 1
                continue
            if days_since > 90:
                invitationsSinceLarger90 += 1
        # Calculate guests with no signin since a long time
        noSignInLarger90 = 0
        noSignInLarger180 = 0
        noSignInLarger365 = 0
        acceptedGuests = get_msgraph_value(
            "/users/",
            {
                "$select": "userPrincipalName,externalUserState,signInActivity",
                "$filter": "externalUserState eq 'Accepted'"
             },
             msGraphTokenForAzCli
        )

        if acceptedGuests != None: # If no global admin rights, the query will likely fail        
            for guest in acceptedGuests:
                if "signInActivity" not in guest:
                    # TODO: this guest has never logged in, check creation date and maybe report it
                    continue
                interactive_date_string = guest["signInActivity"]["lastSignInDateTime"] # format '2023-04-25T07:36:44Z'
                if interactive_date_string != None:
                    interactive_given_datetime = datetime.fromisoformat(interactive_date_string[:-1]) # convert the input string to a datetime object
                    interactive_days_since = (current_datetime - interactive_given_datetime).days # calculate the number of days between the given datetime and the current datetime            
                else:
                    interactive_days_since = 0 # Never logged in interactively?
                non_interactive_date_string = guest["signInActivity"]["lastNonInteractiveSignInDateTime"] # format '2023-04-25T07:36:44Z'
                if non_interactive_date_string != None:
                    non_interactive_given_datetime = datetime.fromisoformat(non_interactive_date_string[:-1]) # convert the input string to a datetime object
                    non_interactive_days_since = (current_datetime - non_interactive_given_datetime).days # calculate the number of days between the given datetime and the current datetime
                else:
                    non_interactive_days_since = 0 # Never logged in non-interactively?
                days_since_last_interaction = max(interactive_days_since, non_interactive_days_since)
                if days_since_last_interaction > 365:
                    noSignInLarger365 += 1
                    noSignInLarger180 += 1
                    noSignInLarger90 += 1
                    continue
                if days_since_last_interaction > 180:
                    noSignInLarger180 += 1
                    noSignInLarger90 += 1
                    continue
                if days_since_last_interaction > 90:
                    noSignInLarger90 += 1
    if groups != None:
        groupNum = len(groups)
        # These are m365 groups that get created in public teams, should be modifiable (add memberships)
        modifiableGroups = [group for group in groups if group["visibility"] == "Public"]
        modifiableGroupsNum = len(modifiableGroups)
    if servicePrincipals != None:
        nativeServicePrincipals = [spn for spn in servicePrincipals if spn["appOwnerOrganizationId"] == tenantId]
        nativeServicePrincipalsNum = len(nativeServicePrincipals)
        servicePrincipalNum = len(servicePrincipals)
    
    appRegistrations = get_msgraph_value("/applications", {}, msGraphToken)
    if appRegistrations == None:
        print_error("Could not fetch App Registrations")
    
    subscriptionsRaw = get_arm("/subscriptions", {}, armToken)
    if subscriptionsRaw == None:
        print_error("Could not fetch subscriptions")
    else:
        subscriptions = subscriptionsRaw["value"]

    # MFA Methods per User
    if userRegistrationDetails != None:
        usersWithoutMfa = [userRegistrationDetail for userRegistrationDetail in userRegistrationDetails if not userRegistrationDetail["isMfaCapable"]]
        usersWithoutMfaNum = len(usersWithoutMfa)
        mfaPercent = round(usersWithoutMfaNum / userNum * 100, 2)

    print_header("Basic information")

    print_info(f"TenantID: {tenantId}")
    print_info(f"License: {aadPlan}")
    print_info(f"Size quota: {objNum}/{objLimit}")
    print_info(f"Display name: {displayName}")
    print_info(f"On Premises Sync: {onPremisesSyncEnabled}")
    if users != None:
        print_info(f"Users: {userNum}")
        print_info(f"Guest Users: {guestNum}/{userNum} ({guestPercent} %)")
        print_info(f"Pending invitations: {pendingInvitationsNum}")
        if invitationsSinceLarger90 > 0:
            print_low(f"Pending invitations waiting for more than 90 days: {invitationsSinceLarger90}")
        if invitationsSinceLarger180 > 0:
            print_low(f"Pending invitations waiting for more than 180 days: {invitationsSinceLarger180}")
        if invitationsSinceLarger365 > 0:
            print_low(f"Pending invitations waiting for more than 365 days: {invitationsSinceLarger365}")
        if acceptedGuests != None:
            if noSignInLarger90 > 0:
                print_low(f"Guests with no signin for more than 90 days: {noSignInLarger90}")
            if noSignInLarger180 > 0:
                print_low(f"Guests with no signin for more than 180 days: {noSignInLarger180}")
            if noSignInLarger365 > 0:
                print_low(f"Guests with no signin for more than 365 days: {noSignInLarger365}")
    if userRegistrationDetails != None:
        print_info(f"Users with no MFA methods: {usersWithoutMfaNum}/{userNum} ({mfaPercent} %)")
    if groups != None:
        print_info(f"Groups: {groupNum}")
        print_info(f"Modifiable groups: {modifiableGroupsNum} (Get them with `az ad group list | jq '.[] | select(.visibility == \"Public\").displayName'`)")
    if servicePrincipals != None:
        print_info(f"Service Principals: {servicePrincipalNum} (aka. \"Enterprise applications\")")
        print_info(f"Service Principals with AppRegs in this tenant: {nativeServicePrincipalsNum}") 
    if appRegistrations != None:
        print_info(f"Application Definitions: {len(appRegistrations)} (aka. \"App registrations\")")
    if subscriptionsRaw != None:
        print_info(f"Subscriptions: {len(subscriptions)}")
        for subscription in subscriptions:
            subName = subscription["displayName"]
            print_simple(f"- {subName}")
    print_simple("")

    # LockoutPolicy
    if groupSettings != None:
        passwdRuleSettings = next((setting for setting in groupSettings if setting["displayName"] =="Password Rule Settings"), None)
        lockoutDurationSeconds = 60 # default
        lockoutThreshold = 10 # default
        if passwdRuleSettings != None:
            lockoutDurationSeconds = next((val["value"] for val in passwdRuleSettings["values"] if val["name"] == "LockoutDurationInSeconds"),None)
            lockoutThreshold = next((val["value"] for val in passwdRuleSettings["values"] if val["name"] == "LockoutThreshold"),None)
        print_info(f"Lockout Threshold: {lockoutThreshold}")
        print_info(f"Lockout Duration Seconds: {lockoutDurationSeconds}")
        print_simple("")

    # Security Defaults
    # Following command should get them
    # az rest --method get --url "{MS_GRAPH_API}/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
    # also here: https://main.iam.ad.ext.azure.com/api/SecurityDefaults/GetSecurityDefaultStatus
    print_info(f"Check if \"Security Defaults\" are enabled: {AZURE_PORTAL}/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Properties")

def enum_user_settings(authPolicy, groupSettings):
    print_header("General user settings")
   
    # App Consent Policy
    if authPolicy != None:
        grantPolicies = authPolicy["permissionGrantPolicyIdsAssignedToDefaultUserRole"] # https://portal.azure.com/?feature.msaljs=false#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/UserSettings
        
        print_link(f"Portal: {AZURE_PORTAL}/?feature.msaljs=false#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/UserSettings")   
        if "ManagePermissionGrantsForSelf.microsoft-user-default-legacy" in grantPolicies:
            print_med("Allow user consent for apps")
        elif "ManagePermissionGrantsForSelf.microsoft-user-default-low" in grantPolicies:
            print_low("Allow user consent for apps from verified publishers, for selected permissions")
        else:
            print_info("Do not allow user consent")
    
    # App consent group settings
    if groupSettings != None:
        consentPolicySettings = next((setting for setting in groupSettings if setting["displayName"] == "Consent Policy Settings"), None)
        enableAdminConsentRequests = "false" # default, https://portal.azure.com/?feature.msaljs=false#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/AdminConsentSettings
        # blockUserConsentForRiskyApps = "false" # ??
        if consentPolicySettings != None:
            enableAdminConsentRequests = next((val["value"] for val in consentPolicySettings["values"] if val["name"] == "EnableAdminConsentRequests"),None)
            #blockUserConsentForRiskyApps = consentPolicySettings["BlockUserConsentForRiskyApps"] ??
        print_link(f"Portal: {AZURE_PORTAL}/?feature.msaljs=false#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/AdminConsentSettings")
        #print_info(f"Block user consent for risky apps: {blockUserConsentForRiskyApps}")
        print_info(f"Users can request admin consent to apps they are unable to consent to: {enableAdminConsentRequests}\n")
    
    if authPolicy != None:
        allowInvitesFrom = authPolicy["allowInvitesFrom"]
        guestUserRole = authPolicy["guestUserRoleId"]
        userCanReadOtherUsers = authPolicy["defaultUserRolePermissions"]["allowedToReadOtherUsers"]

        # Some security settings are just not visible in the Portal, they can be read/set over the Graph API though
        print_link("Portal: NOT visible in the Portal!")
        if userCanReadOtherUsers == True:
            print_info("Users can read other users information (You can actually block this with the Graph API!)")
        else:
            print_info("Users can not read other users information")
        print_simple("")

        print_link(f"Portal: {AZURE_PORTAL}/?feature.msaljs=false#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/UserSettings")
        # create apps
        allowCreateApps = authPolicy["defaultUserRolePermissions"]["allowedToCreateApps"]
        if allowCreateApps == True:
            print_low(f"Users can register applications")
        else:
            print_info(f"Users can not register applications")
        # create tenants
        allowCreateTenants = authPolicy["defaultUserRolePermissions"]["allowedToCreateTenants"]
        if allowCreateTenants == True:
            print_low(f"Users can create tenants")
        else:
            print_info(f"Users can not create tenants")
       
        print_simple("")
        print_link(f"Portal: {AZURE_PORTAL}/?feature.msaljs=false#view/Microsoft_AAD_IAM/AllowlistPolicyBlade")
        # Invitation Policy setting
        if allowInvitesFrom == "adminsGuestInvitersAndAllMembers":
            print_low("Member users and users assigned to specific admin roles can invite guest users including guests with member permissions")
        elif allowInvitesFrom == "everyone": # default
            print_med("Anyone in the organization can invite guest users including guests and non-admins (most inclusive)")
        elif allowInvitesFrom == "adminsAndGuestInviters":
            print_info("Only users assigned to specific admin roles can invite guest users")
        elif allowInvitesFrom == "none":
            print_info("No one in the organization can invite guest users including admins (most restrictive)")
        else:
            print_error(f"Unknown Guest Invite Policy: {allowInvitesFrom}")

        # Guest User permissions
        if guestUserRole == GUEST_ROLE_USER:
            print_med("Guest users have the same access as members (most inclusive)")
        elif guestUserRole == GUEST_ROLE_GUEST:
            print_low("Guest users have limited access to properties and memberships of directory objects")
        elif guestUserRole == GUEST_ROLE_RESTRICTED:
            print_info("Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)")
        else:
            print_error(f"Unknown Guest Role ID: {guestUserRole}")
      
    # Group Creation settings
    if groupSettings != None:
        groupUnifiedSettings = next((setting for setting in groupSettings if setting["templateId"] == GROUP_UNIFIED_TEMPLATE_ID), None)
        enableAdGroupCreation = True # default, https://portal.azure.com/?feature.msaljs=false#view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/General
        if groupUnifiedSettings != None:
            enableAdGroupCreation = next((val["value"] for val in groupUnifiedSettings["values"] if val["name"] == "EnableGroupCreation"),None)
        allowedToCreateSecurityGroups = authPolicy["defaultUserRolePermissions"]["allowedToCreateSecurityGroups"] # https://portal.azure.com/?feature.msaljs=false#view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/General
        print_simple("")
        print_link(f"Portal: {AZURE_PORTAL}/?feature.msaljs=false#view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/General")
        # create AD groups
        if enableAdGroupCreation == True:
            print_low("Users can create m365 groups")
        else:
            print_info("Users can not create m365 groups")
        # create AD security groups
        if allowedToCreateSecurityGroups == True:
            print_low(f"Users can create security groups\n")
        else:
            print_info(f"Users can not create security groups\n")
    
def enum_device_settings(authPolicy, tenantId, aadGraphToken):
    print_header("Device Settings")
    print_link(f"Portal: {AZURE_PORTAL}/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/DeviceSettings/menuId~/null")
    print_info("If \"Users may join devices to Azure AD\" is enabled you may be able to create BPRT users, bypass the device quota, and provoke DoS: https://aadinternals.com/post/bprt/")
    
    # Bitlocker keys policy
    if authPolicy != None:
        allowReadBitlocker = authPolicy["defaultUserRolePermissions"]["allowedToReadBitlockerKeysForOwnedDevice"]
        if allowReadBitlocker == True:
            print_med("Users can recover Bitlocker Keys of owned devices")
        else:
            print_info("Users can not recover Bitlocker Keys of owned devices")
    
    # I wonder if using FOCI clients I can get this endpoint? "https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy"

    # Registration quota, note that if device join/registration is disabled, this becomes irrelevant
    deviceConfiguration = get_aadgraph_value("/deviceConfiguration", {}, tenantId, aadGraphToken)
    if deviceConfiguration is not None and len(deviceConfiguration) > 0:
        reg_quota = deviceConfiguration[0]["registrationQuota"]
        print_info(f"Maximum number of devices per user: {reg_quota}")

def enum_admin_roles(msGraphToken, userRegistrationDetails):
    print_header("Administrative Roles")

    directoryRoles = get_msgraph_value("/directoryRoles", {"$expand": "members"}, msGraphToken)
    if directoryRoles == None:
        print_error(f"Could not fetch administrative roles")
        return
    for directoryRole in directoryRoles:
        memberCount = len(directoryRole["members"])
        if memberCount == 0:
            continue
        roleName = directoryRole["displayName"]
        principalsInRole = directoryRole["members"]
        print_info(f"{roleName}: {len(principalsInRole)}")
        for principal in principalsInRole:
            displayName = principal["displayName"]
            if principal["@odata.type"] == "#microsoft.graph.group":
                synced = "{ORANGE}(synced!){NC}" if principal["onPremisesSyncEnabled"] else ""
                print_simple(f"- [GROUP] ({displayName}) {synced}")
            elif principal["@odata.type"] == "#microsoft.graph.user":
                userPrincipalName = principal["userPrincipalName"]
                userHasMfa = hasUserMFA(userPrincipalName, userRegistrationDetails)
                lacksMfa = "" if userHasMfa else f" {ORANGE}(No MFA Methods!){NC}"
                if userHasMfa == None:
                    lacksMfa = " (MFA unknown)"
                synced = f" {ORANGE}(synced!){NC}" if principal["onPremisesSyncEnabled"] else ""
                print_simple(f"- [USER] {userPrincipalName} ({displayName}){synced}{lacksMfa}")
            elif principal["@odata.type"] == "#microsoft.graph.servicePrincipal":
                print_simple(f"- [SERVICE] ({displayName})")
            else:
                principalType = principal["@odata.type"]
                print_error(f"Unknown principal type: {principalType}")

def hasUserMFA(userPrincipalName, userRegistrationDetails):   
    if userRegistrationDetails == None:
        # Information on MFA could not be fetched
        return None # unknown whether MFA methods are set

    # pick user mfa methods
    registrationDetail = next((registrationDetail for registrationDetail in userRegistrationDetails if registrationDetail["userPrincipalName"] == userPrincipalName), None)
    
    if registrationDetail == None:
        print_error(f"User not found: {userPrincipalName}")
        return None
    
    return registrationDetail["isMfaCapable"]

def enum_pim_assignments(users, powerAutomateAccessToken, userRegistrationDetails):
    print_header("PIM Assignments")

    eligibleAssignments = get_msgraph_value(
        "/roleManagement/directory/roleEligibilitySchedules",
        params={ "$expand": "principal,roleDefinition" },
        token=powerAutomateAccessToken
    )

    activeAssignments = get_msgraph_value(
        "/roleManagement/directory/roleAssignmentSchedules",
        params={ "$expand": "principal,roleDefinition" },
        token=powerAutomateAccessToken
    )

    if eligibleAssignments == None or activeAssignments == None:
        # PIM assignments could not be fetched, return
        return

    results = eligibleAssignments + activeAssignments
    roles = set([result["roleDefinition"]["displayName"] for result in results])
    for role in roles:
        assignments = [result for result in results if result["roleDefinition"]["displayName"] == role]
        count = len(assignments)
        print_info(f"{role}: {count}")
        # If assignment expired, its not shown
        for assignment in assignments:
            principalId = assignment["principal"]["id"]
            displayName = assignment["principal"]["displayName"]
            type = assignment["principal"]["@odata.type"]

            # Parameters will be set for user objects
            lacksMfa = ""
            synced = ""

            if type == "#microsoft.graph.user":
                principalId = assignment["principal"]["userPrincipalName"] # for users, show UPN instead of ID
                friendlyType = "USER"
                # Check whether synced & no MFA methods
                userHasMfa = hasUserMFA(principalId, userRegistrationDetails)
                lacksMfa = "" if userHasMfa else f" {ORANGE}(No MFA Methods!){NC}"
                if userHasMfa == None:
                    lacksMfa = " (MFA unknown)"
                userObject = next((user for user in users if user["userPrincipalName"] == principalId), None)
                if userObject == None:
                    synced = f" {RED}(user not found!){NC}"
                else:
                    synced = f" {ORANGE}(synced!){NC}" if userObject["onPremisesSyncEnabled"] else ""
            elif type == "#microsoft.graph.group":
                friendlyType = "GROUP"
            elif type == "#microsoft.graph.servicePrincipal":
                friendlyType = "SERVICE_PRINCIPAL"
            else:
                friendlyType = "UNKNOWN_TYPE"
            
            isPermanent = f"{RED}[Permanent]{NC}" if assignment["scheduleInfo"]["expiration"]["type"] == "noExpiration" else ""
            assignmentState = "Active" if "assignmentType" in assignment else "Eligible"
            stateText = f"{GREEN}[{assignmentState}]{NC}"
            print_simple(f"- [{friendlyType}] {principalId} ({displayName}) {isPermanent}{stateText}{synced}{lacksMfa}")

def enum_app_api_permissions(servicePrincipals, tenantId, msGraphToken):
    print_header("ServicePrincipal API Permissions")
    # In principle I am only interested in SPs from an AppReg. I can fetch the AppRegs `az rest --method get --url "{MS_GRAPH_API}/v1.0/myorganization/applications/"` and then lookout their SPs by checking the "appId" field of the SP object
    # Once I got the SP I can ask the appRoleAssignments like this `az rest --method get --url '{MS_GRAPH_API}/v1.0/servicePrincipals/<servicePrincipalId>/appRoleAssignments'` which get me value[] with objects like {resourceId,resourceDisplayName,appRoleId,...}. I need to pick the resourceId and the appRoleId to ask for the API-Permissions in the next request
    # I go {MS_GRAPH_API}/v1.0/servicePrincipals/<resourceId> and ask for the "appRoles" which look like {id,value,displayName}. The id is the "appRoleId" from before, the value is the API-Permission and the displayname a short description

    # SP that has an AppReg in the tenant
    internalSps = [sp for sp in servicePrincipals if sp["appOwnerOrganizationId"] == tenantId]
    # SP that has not an AppReg in the tenant. Nicht interessiert in Apps, die Microsoft gehören
    externalSps = [sp for sp in servicePrincipals if sp["appOwnerOrganizationId"] not in {tenantId, MICROSOFT_SERVICE_TENANT_ID}]
    
    if len(internalSps) > 0:
        print_info(f"ServicePrincipals with an AppReg in this tenant")
    for sp in internalSps:
        id = sp["id"]
        displayName = sp["displayName"]
        appRoleAssignments = get_msgraph_value(f"/servicePrincipals/{id}/appRoleAssignments", {}, msGraphToken)
        if len(appRoleAssignments) > 0:
            for appRoleAssignment in appRoleAssignments:
                # For each appRoleAssignment
                resourceId = appRoleAssignment["resourceId"] # where does this app has an api permission (ID)
                appRoleId = appRoleAssignment["appRoleId"] # which permission does the app has
                resourceDisplayName = appRoleAssignment["resourceDisplayName"] # where does this app has an api permission
                resourceServicePrincipalAppRoles = next((sp["appRoles"] for sp in servicePrincipals if sp["id"] == resourceId), None)
                if (resourceServicePrincipalAppRoles != None):
                    appRole = next((appRole for appRole in resourceServicePrincipalAppRoles if appRole["id"] == appRoleId), None)
                    if appRole != None:
                        apiPermissionName = appRole["value"]
                        print_info(f"- {GREEN}[{displayName}]{NC} has {ORANGE}[{apiPermissionName}]{NC} in {CYAN}[{resourceDisplayName}]{NC}")
                    else:
                        # could not enumerate permission name, write down ID
                        print_info(f"- {GREEN}[{displayName}]{NC} has {ORANGE}[{appRoleId}]{NC} in {CYAN}[{resourceDisplayName}]{NC}")
    if len(externalSps) > 0:
        print_info(f"ServicePrincipals with an AppReg in a foreign, non-Microsoft tenant")
    for sp in externalSps:
        id = sp["id"]
        displayName = sp["displayName"]
        appRoleAssignments = get_msgraph_value(f"/servicePrincipals/{id}/appRoleAssignments", {}, msGraphToken)
        if len(appRoleAssignments) > 0:
            for appRoleAssignment in appRoleAssignments:
                # For each appRoleAssignment
                resourceId = appRoleAssignment["resourceId"] # where does this app has an api permission (ID)
                appRoleId = appRoleAssignment["appRoleId"] # which permission does the app has
                resourceDisplayName = appRoleAssignment["resourceDisplayName"] # where does this app has an api permission
                resourceServicePrincipalAppRoles = next((sp["appRoles"] for sp in servicePrincipals if sp["id"] == resourceId), None)
                if (resourceServicePrincipalAppRoles != None):
                    appRole = next((appRole for appRole in resourceServicePrincipalAppRoles if appRole["id"] == appRoleId), None)
                    if appRole != None:
                        apiPermissionName = appRole["value"]
                        print_info(f"- {GREEN}[{displayName}]{NC} has {ORANGE}[{apiPermissionName}]{NC} in {CYAN}[{resourceDisplayName}]{NC}")
                    else:
                        # could not enumerate permission name, write down ID
                        print_info(f"- {GREEN}[{displayName}]{NC} has {ORANGE}[{appRoleId}]{NC} in {CYAN}[{resourceDisplayName}]{NC}")

def enum_administrative_units(msGraphToken):
    print_header("Administrative Units")
    print_link(f"Portal: {AZURE_PORTAL}/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/AdminUnit")
    admUnits = get_msgraph_value("/directory/administrativeUnits", {}, msGraphToken)
    if admUnits == None:
        print_error(f"Could not fetch Administrative Units")
        return
    directoryRoles = get_msgraph_value("/directoryRoles", {}, msGraphToken)
    if directoryRoles == None:
        print_error(f"Could not fetch directory roles")
        return
    admUnitsNum = len(admUnits)
    if admUnitsNum == 0:
        print_info(f"No Administrative Units found")
        return
    
    print_info(f"{admUnitsNum} Administrative Units found")
    for unit in admUnits:
        displayName = unit["displayName"]
        admUnitId = unit["id"]
        membershipType = "Dynamic" if unit["membershipType"] == "Dynamic" else "Assigned"
        membershipRule = unit["membershipRule"] if unit["membershipRule"] != None else ""
        # Get Admin Roles (restricted to this administrative unit)
        admRoles = get_msgraph_value(f"/directory/administrativeUnits/{admUnitId}/scopedRoleMembers", {}, msGraphToken)
        ruleText = f": {membershipRule}" if membershipRule != "" else ""
        print_info(f"- {GREEN}[{membershipType}] {displayName}{NC}{ruleText}")
        for admRole in admRoles:
            displayName = admRole["roleMemberInfo"]["displayName"]
            roleId = admRole["roleId"]
            roleName = next((role["displayName"] for role in directoryRoles if role["id"] == roleId), None)
            print_info(f"  - {displayName} has role {roleName}")

def enum_dynamic_groups(groups):
    if groups == None:
        return # Couldnt fetch groups before
    dynamicGroups = [group for group in groups if "DynamicMembership" in group["groupTypes"]]
    print_header("Dynamic groups")
    print_link("Exploitation: https://cloud.hacktricks.xyz/pentesting-cloud/azure-pentesting/dynamic-groups")
    print_info(f"{len(dynamicGroups)} Dynamic Groups found")
    if len(dynamicGroups) == 0:
        return
    for group in dynamicGroups:
        displayName = group["displayName"]
        membershipRule = group["membershipRule"]
        groupType = "Security"
        if "Unified" in group["groupTypes"]:
            groupType = "m365"
        print_info(f"- {GREEN}[{groupType}] {displayName}{NC}: {membershipRule}")

def enum_named_locations(msGraphToken):
    print_header("Named Locations")
    print_link(f"Portal: {AZURE_PORTAL}/?feature.msaljs=false#view/Microsoft_AAD_ConditionalAccess/NamedLocationsBlade")
    
    namedLocations = get_msgraph_value("/identity/conditionalAccess/namedLocations", {}, msGraphToken)
        
    if namedLocations == None:
        print_error(f"Could not fetch named locations")
        return
    
    if len(namedLocations) == 0:
        print_info("No named locations")
        return
    
    print_info(f"{len(namedLocations)} Named locations found")
    for location in namedLocations:
        displayName = location["displayName"]
        locationType = location["@odata.type"]
        if locationType == "#microsoft.graph.ipNamedLocation":
            ranges = ' '.join([ipRange["cidrAddress"] for ipRange in location["ipRanges"]])
            isTrusted = "Trusted" if location["isTrusted"] else "Not trusted"
            print_info(f"- {GREEN}[IP - {isTrusted}] {displayName}{NC} {ranges}")
        elif locationType == "#microsoft.graph.countryNamedLocation":
            countries = ' '.join(location["countriesAndRegions"])
            print_info(f"- {GREEN}[COUNTRY] {displayName}{NC} {countries}")
        else:
            print_info(f"- {GREEN}[Unknown Location type: {locationType}] {displayName}{NC}")

def enum_conditional_access(tenantId, aadGraphToken):
    print_header("Conditional Access Policies")
    print_link(f"Portal: {AZURE_PORTAL}/?feature.msaljs=false#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies")
    
    allPolicies = get_aadgraph_value("/policies", {}, tenantId, aadGraphToken)
    if allPolicies == None:
        print_error("Could not fetch Conditional Access Policies")
        return
    conditionalAccessPolicies = [policy for policy in allPolicies if policy["policyType"]==18] # what are the other policies??
    if len(conditionalAccessPolicies) == 0:
        print_info("No Conditional Access Policies")
        return
    
    print_info(f"{len(conditionalAccessPolicies)} Conditional Access Policies found")
    for cap in conditionalAccessPolicies:
        displayName = cap["displayName"]
        detailsRaw = cap["policyDetail"][0]
        details = json.loads(detailsRaw)
        isEnabled = details["State"]
        color = RED
        if isEnabled == "Enabled":
            color = GREEN
        elif isEnabled == "Reporting":
            color = ORANGE
        print_info(f"- {color}[{isEnabled}]{NC} {GREEN}\"{displayName}\"{NC}")

def enum_devices(msGraphToken):
    print_header("Devices")
    print_link(f"Portal: {AZURE_PORTAL}/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/Devices/menuId~/null")
    devices = get_msgraph_value("/devices", {"$top": "999"}, msGraphToken)

    if devices == None:
        print_error("Could not fetch devices")
        return
    
    print_info(f"Number of devices: {len(devices)}")
    print_info("Devices per Join-Type:")
    registeredDevices = [device for device in devices if device["trustType"] == "Workplace"]
    joinedDevices = [device for device in devices if device["trustType"] == "AzureAd"]
    hybridJoinedDevices = [device for device in devices if device["trustType"] == "ServerAd"]
    print_info(f"- Registered: {len(registeredDevices)}")
    print_info(f"- Joined: {len(joinedDevices)}")
    print_info(f"- Hybrid-Joined: {len(hybridJoinedDevices)}")
    managedDevices = [device for device in devices if device["isManaged"] == True]
    managedPercent = "-"
    if len(devices) != 0:
        managedPercent = round(len(managedDevices) / len(devices) * 100, 2)
    print_info(f"Managed devices: {len(managedDevices)}/{len(devices)} ({managedPercent} %)")
    compliantDevices = [device for device in devices if device["isCompliant"] == True]
    nonCompliantDevices = [device for device in devices if device["isCompliant"] == False]
    deviceNumWithComplianceData = len(compliantDevices) + len(nonCompliantDevices)
    compliantPercent = "-"
    if deviceNumWithComplianceData != 0:
        compliantPercent = round(len(compliantDevices) / deviceNumWithComplianceData * 100, 2)
    print_info(f"Compliant devices: {len(compliantDevices)}/{deviceNumWithComplianceData} ({compliantPercent} %)")
    
    current_datetime = datetime.utcnow()
    # Calculate 6 months ago from the current date
    six_months_ago = current_datetime - timedelta(days=6*30)  # Approximate 30 days in a month
    formatted_datetime = six_months_ago.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    staleDevices = get_msgraph_value("/devices", {
        "$top": "999",
        "$filter": f"approximateLastSignInDateTime le {formatted_datetime}"
    }, msGraphToken)
    staleProcent = "-"
    if len(devices) != 0:
        staleProcent = round(len(staleDevices)/len(devices) * 100, 2)
    print_info(f"Stale Devices: {len(staleDevices)}/{len(devices)} ({staleProcent} %) -- last activity older than 6 months")

    
def search_principal_properties(groups, servicePrincipals, msGraphToken):
    print_header("Juicy Info in User, Group and Apps Properties")
    print_info("Searching for juicy info in principal properties ...")
    keywords = ["passwo", "credential", "access", "zugang", "login", "anmeld", "initial"]
    
    usersFull = get_msgraph_value("/users", {}, msGraphToken, "beta")
    if usersFull == None:
        print_error(f"Could not fetch users")
    else:    
        for user in usersFull:
            for key in user:
                if (isinstance(user[key], str) and key != "passwordPolicies"): # Exclude "passwordPolicies" string which leads to false positives
                    if any(keyword in user[key].lower() for keyword in keywords):
                        upn = user["userPrincipalName"]
                        print_info(f"[USER] {upn} => {RED}({key}): {user[key]}{NC}")
    if groups != None:
        for group in [group for group in groups if group["description"] != None]:
            if any(keyword in group["description"].lower() for keyword in keywords):
                displayName = group["displayName"]
                desc = group["description"]
                print_info(f"[GROUP] {displayName} => {RED}(description): {desc}{NC}")
    if servicePrincipals != None:
        for spn in servicePrincipals:
            if spn["notes"] != None:
                if any(keyword in spn["notes"].lower() for keyword in keywords):
                    displayName = spn["displayName"]
                    notes = spn["notes"]
                    print_info(f"[APP] {displayName} => {RED}(notes): {notes}{NC}")


def print_banner():
    if args.no_color:
        banner = '''
        AzurEnum
        Created by Enrique Hernández (SySS GmbH)
        '''
    else:
        banner = f'''

         ████████ ██████        
       ██████████ ████████     
     ████████████ ██████████    
   ██████{RED}██████{NC}██ █████  █  █   
  █████{RED}███{NC}███████ █ █ █ ██ ███   AzurEnum
 ██████{RED}███{NC}███████ ██ ███ ██ ███   Created by Enrique Hernández (SySS GmbH)
 ████████{RED}█████{NC}███ █ ███  █  ███  
 ████████████{RED}███{NC}█
  ███████████{RED}███{NC}█
   █████{RED}███████{NC}██
     ████████████ 
       ▄▄▄▄▄▄▄▄▄▄ 
         ████████ 

        '''

    print(banner)


def main():

    global args
    parser = argparse.ArgumentParser(formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=100))
    parser.add_argument("-o", "--output-text", help="specify filename to save TEXT output", default=None, type=argparse.FileType('w'))
    parser.add_argument("-j", "--output-json", help="specify filename to save JSON output (only findings related to insecure settings will be written!)", default=None, type=argparse.FileType('w'))
    parser.add_argument("-nc", "--no-color", help="don't use colors", action='store_true')
    parser.add_argument("-ua", "--user-agent", help="specify user agent (default is MS-Edge on Windows 10)", default=None)
    parser.add_argument("-t", "--tenant-id", help="specify tenant to authenticate to (needed for ROPC authentication or when authenticating to a non-native tenant of the given user)", default=None)
    parser.add_argument("-u", "--upn", help="specify user principal name to use in ROPC authentication", default=None)
    parser.add_argument("-p", "--password", help="specify password to use in ROPC authentication", default=None)
    parser.add_argument("-pr", "--proxy", help="specify a proxy to use in sending requests", default=None)
    args = parser.parse_args()


    if args.user_agent or args.proxy:
        global session
        global query_session

        # Set UA if given
        if args.user_agent != None:
            session.headers.update({"User-Agent": args.user_agent})
            query_session.headers['User-Agent'] = args.user_agent

        if args.proxy != None:
            if args.proxy.startswith('http://'):
                session.proxies = {'https': args.proxy, 'http': args.proxy}
                session.verify = False 
                query_session.proxies = {'https': args.proxy, 'http': args.proxy}
                query_session.verify = False
                requests.packages.urllib3.disable_warnings() 
            else:
                raise Exception('Provide proxy address in format "http://ip:port"')


    # Set Colors
    if args.no_color:
        unset_colors()
    elif IS_WINDOWS:
        # Activate colors for the terminal
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

    print_banner()

    # Start authentication process against Azure with SCOPE_GRAPH and OFFICE_CLIENT_ID
    if args.upn != None and args.password != None and args.tenant_id != None:
        tokens = authenticate_with_msal(OFFICE_CLIENT_ID, SCOPE_MS_GRAPH, ROPC_FLOW, args.upn, args.password)
    else:
        tokens = authenticate_with_msal(OFFICE_CLIENT_ID, SCOPE_MS_GRAPH, DEVICE_CODE_FLOW)
     
    if tokens == None:
        print_error("Could not authenticate to Microsoft Graph. Quitting ...")
        sys.exit(1)

    # msGraphTokenForMsOffice = tokens['access_token'] # token for the client used during authentication
    msGraphRefreshToken = tokens['refresh_token']
    
    if "upn" in tokens['id_token_claims']:
        myUpn = tokens['id_token_claims']['upn']
    else: # if authenticating to a foreign tenant, upn claim is not there
        myUpn = tokens['id_token_claims']['preferred_username']
    
    # Used adquired refresh token to get more tokens of other scopes and FOCI clients
    print_info("Gathering additional access tokens for other FOCI clients and resources ...")
    msGraphTokens = authenticate_with_msal(client_id=AZURECLI_CLIENT_ID, scopes=SCOPE_MS_GRAPH, flow=REFRESH_TOKEN_FLOW, refresh_token=msGraphRefreshToken)
    if msGraphTokens != None:
        msGraphToken = msGraphTokens['access_token']
    else:
        print_error("Could not request Microsoft Graph token")
        msGraphRefreshToken = None
    aadGraphTokens = authenticate_with_msal(client_id=AZURECLI_CLIENT_ID, scopes=SCOPE_AAD_GRAPH, flow=REFRESH_TOKEN_FLOW, refresh_token=msGraphRefreshToken)
    if aadGraphTokens != None:
        aadGraphToken = aadGraphTokens['access_token']
    else:
        print_error("Could not request AAD Graph token")
        aadGraphToken = None
    armTokens = authenticate_with_msal(client_id=AZURECLI_CLIENT_ID, scopes=SCOPE_ARM, flow=REFRESH_TOKEN_FLOW, refresh_token=msGraphRefreshToken)
    if armTokens != None:
        armToken = armTokens['access_token']
    else:
        print_error("Could not request ARM token")
        armToken = None

    # Perform a 2nd authentication to Microsoft Graph with the client POWER_AUTOMATE_CLIENT_ID
    # Need this to grab the PIM assignments later
    if args.upn != None and args.password != None and args.tenant_id != None:
        powerAutomateTokens = authenticate_with_msal(POWER_AUTOMATE_CLIENT_ID, scopes=SCOPE_MS_GRAPH, flow=ROPC_FLOW, username=args.upn, password=args.password)
    else:
        print_info("In order to grab the PIM assignments later, you need to authenticate a second time")
        powerAutomateTokens = authenticate_with_msal(POWER_AUTOMATE_CLIENT_ID, scopes=SCOPE_MS_GRAPH, flow=DEVICE_CODE_FLOW)

    if powerAutomateTokens == None:
        print_error("Could not authenticate with client 'Power Automate Desktop For Windows'. PIM Enumeration will not work.")
        powerAutomateAccessToken = None
    else:
        powerAutomateAccessToken = powerAutomateTokens['access_token']

    print_info(f"Running as {myUpn}")
    print_info(f"Gathering information ............")

    # Gather some data that gets reused by other functions
    org = get_msgraph_value("/organization", {}, msGraphToken)[0]
    groups = get_msgraph_value("/groups", {}, msGraphToken)
    if groups == None:
        print_error("Could not fetch groups")

    servicePrincipals = get_msgraph_value("/servicePrincipals", {}, msGraphToken)
    if servicePrincipals == None:
        print_error(f"Could not fetch Service Principals")
    groupSettings = get_msgraph_value("/groupSettings", {}, msGraphToken)
    if groupSettings == None:
        print_error(f"Could not fetch GroupSettings")
    tenantId = org["id"]

    users = get_msgraph_value(
        "/users", 
        {
            "$select": "displayName,id,userPrincipalName,userType,onPremisesSyncEnabled"
        }, 
        msGraphToken
    )    
    if users == None:
        print_error("Could not fetch users")

    userRegistrationDetails =  get_msgraph_value("/reports/authenticationMethods/userRegistrationDetails", {}, msGraphToken)
    if userRegistrationDetails == None:
        print_error("Could not fetch user MFA methods, no MFA information will be provided!")
        
    # Basic Tenant Info
    basic_info(org, groups, servicePrincipals, groupSettings, users, userRegistrationDetails, msGraphToken, msGraphToken, armToken)

    authPolicy = get_msgraph("/policies/authorizationPolicy/authorizationPolicy", {}, msGraphToken, "beta")
    if authPolicy == None:
        print_error(f"Could not fetch Authorization Policy")

    # General user settings
    enum_user_settings(authPolicy, groupSettings)

    # Device Settings
    enum_device_settings(authPolicy, tenantId, aadGraphToken)

    # Administrators
    enum_admin_roles(msGraphToken, userRegistrationDetails)

    # PIM Assignments
    enum_pim_assignments(users, powerAutomateAccessToken, userRegistrationDetails)

    # API-Permissions
    if servicePrincipals != None:
        enum_app_api_permissions(servicePrincipals, tenantId, msGraphToken)

    # Administrative Units
    enum_administrative_units(msGraphToken)

    # Dynamic groups
    enum_dynamic_groups(groups)

    # Named locations
    enum_named_locations(msGraphToken)

    # Conditional Access
    enum_conditional_access(tenantId, aadGraphToken)

    # Devices
    enum_devices(msGraphToken)

    # Search principals properties for creds
    search_principal_properties(groups, servicePrincipals, msGraphToken)

    if args and args.output_text:
        args.output_text.write(log_content)
        args.output_text.close()
    
    if args and args.output_json:
        args.output_json.write(json.dumps(json_content))
        args.output_json.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_info('KeyboardInterrupt... Exit now!')
        sys.exit(1)
