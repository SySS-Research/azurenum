#!/usr/bin/env python3

import json, sys, requests, platform, ctypes, signal
from alive_progress import alive_bar

#import utils
from azurenum.utils import api, args, auth, const, helper, output, printer, sessions
from azurenum.utils.config import globalconfig as globalconfig
from azurenum.utils.config import globalargs as globalargs
#from azurenum.enums import *
from azurenum.enums.administrative_units import enum_administrative_units as enum_administrative_units
from azurenum.enums.app_api_permissions import enum_app_api_permissions as enum_app_api_permissions
from azurenum.enums.authentication_methods import enum_authentication_methods as enum_authentication_methods
from azurenum.enums.basic_info import enum_basic_info as enum_basic_info
from azurenum.enums.conditional_access import enum_conditional_access as enum_conditional_access
from azurenum.enums.device_settings import enum_device_settings as enum_device_settings
from azurenum.enums.devices import enum_devices as enum_devices
from azurenum.enums.directory_roles import enum_directory_roles as enum_directory_roles
from azurenum.enums.dynamic_groups import enum_dynamic_groups as enum_dynamic_groups
from azurenum.enums.idp_federation import enum_idps as enum_idps
from azurenum.enums.modifiable_groups import enum_modifiable_groups as enum_modifiable_groups
from azurenum.enums.named_locations import enum_named_locations as enum_named_locations
from azurenum.enums.pim_assignments import enum_pim_assignments as enum_pim_assignments
from azurenum.enums.principal_properties import search_principal_properties as search_principal_properties
from azurenum.enums.sspr_settings import enum_sspr_settings as enum_sspr_settings
from azurenum.enums.user_groups_settings import enum_user_settings as enum_user_settings
from azurenum.enums.seamless_sso import enum_seamless_sso as enum_seamless_sso
from azurenum.enums.cross_tenant_access import enum_cross_tenant_access as enum_cross_tenant_access




if platform.system() == 'Windows':
    IS_WINDOWS = True
else:
    IS_WINDOWS = False

### keyboardinterrupt catches
def signal_handler(signum, frame):
    print(f"\n\n{const.ORANGE}[!]{const.NC}Ctrl+C pressed! Do you really want to quit? (y/N): ", end="", flush=True)

    try:
        # Wait for user input
        user_input = input().strip().lower()
        
        
        if user_input in ['y', 'yes', '^C']:
            print(f"Shutting down gracefully...")
            sys.exit(0)
        else:
            print("Continuing... (press Ctrl+C again to quit)")
    except RuntimeError:
        print(f"\nShutting down gracefully...")
        sys.exit(0)
    except KeyboardInterrupt:
        # Ctrl+C pressed during input → treat as "y"
        print("Shutting down gracefully...")
        sys.exit(0)
    except Exception as e:
        print(f"\nError reading input: {e}")
        print("Continuing...")

signal.signal(signal.SIGINT, signal_handler)

def unset_colors():
    # global RED, GREEN, YELLOW, CYAN, ORANGE, NC
    const.RED = const.GREEN = const.YELLOW = const.CYAN = const.ORANGE = const.NC = ""
    
def main():
    args.parse_args()

    if globalargs.user_agent or globalargs.proxy:
        # Set UA if given
        if globalargs.user_agent:
            sessions.auth_session.headers.update({"User-Agent": globalargs.user_agent})
            sessions.query_session.headers["User-Agent"] = globalargs.user_agent
        # set proxy if given
        if  globalargs.proxy != None:
            if globalargs.proxy.startswith('http://'):
                sessions.auth_session.proxies = {'https': globalargs.proxy, 'http': globalargs.proxy}
                sessions.auth_session.verify = False
                sessions.query_session.proxies = {'https': globalargs.proxy, 'http': globalargs.proxy}
                sessions.query_session.verify = False
                requests.packages.urllib3.disable_warnings()
            else:
                printer.print_error('Provide proxy address in format "http://ip:port"')
                sys.exit(1)
    # Set Colors
    if globalargs.no_color:
        unset_colors()

    elif IS_WINDOWS:
        # Activate colors for the terminal
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

    printer.print_banner()

    
    # Start authentication process against Azure with SCOPE_GRAPH and const.OFFICE_CLIENT_ID
    if globalargs.upn != None and globalargs.password != None and globalargs.tenant_id != None:
        tokens = auth.authenticate_with_msal(const.OFFICE_CLIENT_ID, const.SCOPE_MS_GRAPH, const.ROPC_FLOW, globalargs.upn, globalargs.password)
    elif globalargs.refresh_token != None:
        tokens = auth.authenticate_with_msal(client_id=const.OFFICE_CLIENT_ID, scopes=const.SCOPE_MS_GRAPH, flow=const.REFRESH_TOKEN_FLOW, refresh_token=globalargs.refresh_token)
    elif globalargs.nested_app_auth != None: # naa RT passed directly
        tokens = auth.do_broker_authentication(globalargs.nested_app_auth)
        if tokens != None:
            globalargs.policies = True
            globalargs.identity_provider = True
    elif globalargs.interactive_auth:
        tokens = auth.do_interactive_auth(upn=globalargs.upn, password=globalargs.password, tenant_id=globalargs.tenant_id) # getting tokens from portal
        if tokens != None:
            globalargs.nested_app_auth = tokens["refresh_token"]
            tokens = auth.do_broker_authentication(globalargs.nested_app_auth) # getting brokered token -- refreshtoken will remain the same
            globalargs.policies = True
            globalargs.identity_provider = True
    elif globalargs.device_code:
        tokens = auth.authenticate_with_msal(const.OFFICE_CLIENT_ID, const.SCOPE_MS_GRAPH, const.DEVICE_CODE_FLOW)
    else: # default to interactive NAA
        tokens = auth.do_interactive_auth(upn=globalargs.upn, password=globalargs.password, tenant_id=globalargs.tenant_id) # getting tokens from portal
        if tokens != None:
            globalargs.nested_app_auth = tokens["refresh_token"]
            tokens = auth.do_broker_authentication(globalargs.nested_app_auth) # getting brokered token -- refreshtoken will remain the same
            globalargs.policies = True
            globalargs.identity_provider = True

    if tokens == None:
        printer.print_error("Could not authenticate to Microsoft Graph. Quitting ...")
        sys.exit(1)

    infoBlocks = 20 if globalargs.nested_app_auth == None else 26 # prepare progress bar
    msGraphRefreshToken = tokens['refresh_token']
    ### Another Login flow for Polcies.ReadWrite.All if using legacy auth
    policyAccessToken = None if globalargs.nested_app_auth == None else tokens["access_token"]
    if globalargs.policies and globalargs.nested_app_auth == None: 
        printer.print_warning("To query Policies we need another log in.....")
        if globalargs.upn != None and globalargs.password != None and globalargs.tenant_id != None and globalargs.nested_app_auth == None:
            policyTokens = auth.authenticate_with_msal(const.MODERN_WORKPLACE_CUSTOMER_API_NATIVE_CLIENT_ID, const.SCOPE_MS_GRAPH, const.ROPC_FLOW, globalargs.upn, globalargs.password)
        else:
            policyTokens = auth.authenticate_with_msal(const.MODERN_WORKPLACE_CUSTOMER_API_NATIVE_CLIENT_ID, const.SCOPE_MS_GRAPH, const.DEVICE_CODE_FLOW)
        infoBlocks += 4
        policyAccessToken = policyTokens["access_token"]

    ### Another Login flow for IdentityProvider.Read.All if using legacy auth
    idpAccessToken = None if globalargs.nested_app_auth == None else tokens["access_token"]
    if globalargs.identity_provider and globalargs.nested_app_auth == None: 
        printer.print_warning("To query IDP settings, we need another log in.....")
        if globalargs.upn != None and globalargs.password != None and globalargs.tenant_id != None:
            idpTokens = auth.authenticate_with_msal(const.AAD_POWERSHELL_CLIENT_ID, const.SCOPE_MS_GRAPH, const.ROPC_FLOW, globalargs.upn, globalargs.password)
        else:
            idpTokens = auth.authenticate_with_msal(const.AAD_POWERSHELL_CLIENT_ID, const.SCOPE_MS_GRAPH, const.DEVICE_CODE_FLOW)
        infoBlocks += 2
        idpAccessToken = idpTokens["access_token"]


    myUpn = helper.decode_jwt(tokens["access_token"])["upn"]
    
    # Used acquired refresh token to get more tokens of other scopes and FOCI clients
    printer.print_info("Gathering additional access tokens for other FOCI/NAA clients and resources ...")
    msGraphTokens = auth.authenticate_with_msal(client_id=const.AZURECLI_CLIENT_ID, scopes=const.SCOPE_MS_GRAPH, flow=const.REFRESH_TOKEN_FLOW, refresh_token=msGraphRefreshToken) if globalargs.nested_app_auth == None else tokens
    if msGraphTokens != None:
        msGraphToken = msGraphTokens['access_token']
    else:
        printer.print_error("Could not request Microsoft Graph token")
        msGraphRefreshToken = None
    aadGraphTokens = auth.authenticate_with_msal(client_id=const.AZURECLI_CLIENT_ID, scopes=const.SCOPE_AAD_GRAPH, flow=const.REFRESH_TOKEN_FLOW, refresh_token=msGraphRefreshToken) if globalargs.nested_app_auth == None else auth.do_broker_authentication(refresh_token=globalargs.nested_app_auth, scope=const.SCOPE_AAD_GRAPH)
    if aadGraphTokens != None:
        aadGraphToken = aadGraphTokens['access_token']
    else:
        printer.print_error("Could not request AAD Graph token")
        aadGraphToken = None
    armTokens = auth.authenticate_with_msal(client_id=const.AZURECLI_CLIENT_ID, scopes=const.SCOPE_ARM, flow=const.REFRESH_TOKEN_FLOW, refresh_token=msGraphRefreshToken) if globalargs.nested_app_auth == None else auth.do_broker_authentication(refresh_token=globalargs.nested_app_auth, scope=const.SCOPE_ARM)
    if armTokens != None:
        armToken = armTokens['access_token']
    else:
        printer.print_error("Could not request ARM token")
        armToken = None
    pimTokens = auth.authenticate_with_msal(client_id=const.MANAGED_MEETING_ROOMS_CLIENT_ID, scopes=const.SCOPE_MS_GRAPH, flow=const.REFRESH_TOKEN_FLOW, refresh_token=msGraphRefreshToken) if globalargs.nested_app_auth == None else auth.do_broker_authentication(client_id=const.ELMADMIN_CLIENT_ID, refresh_token=globalargs.nested_app_auth, redirect_uri=const.AZURE_PORTAL_BROKER_URI, origin=const.AZURE_PORTAL)
    if pimTokens != None:
        pimToken = pimTokens['access_token']
    else:
        printer.print_error("Could not request PIM token")
        pimToken = None
    mainIamTokens = auth.authenticate_with_msal(client_id=const.AZURECLI_CLIENT_ID, scopes=const.SCOPE_MAIN_IAM, flow=const.REFRESH_TOKEN_FLOW, refresh_token=msGraphRefreshToken) if globalargs.nested_app_auth == None else auth.do_broker_authentication(refresh_token=globalargs.nested_app_auth, scope=const.SCOPE_MAIN_IAM)
    if mainIamTokens != None:
        mainIamAccessToken = mainIamTokens['access_token']
    else:
        printer.print_error("Could not request Main IAM token")
        msGraphRefreshToken = None
    printer.print_info(f"Running as {myUpn}")
    printer.print_info(f"Gathering information............")

    # Gather data 
    with alive_bar(infoBlocks, bar='blocks',receipt=False, length=40, enrich_print=False, title='') as bar:
        org = api.get_msgraph_value("/organization", {}, msGraphToken)[0]
        
        # groups with approleassignments
        groups = api.get_msgraph_value("/groups", "$expand=appRoleAssignments", msGraphToken)
        if groups == None:
            printer.print_error("Could not fetch groups")
        bar()

        # service principals
        servicePrincipals = api.get_msgraph_value("/servicePrincipals", "$expand=owners", msGraphToken)
        if servicePrincipals == None:
            printer.print_error(f"Could not fetch Service Principals")
        else:
            globalconfig.servicePrincipals = servicePrincipals
        bar()

        # application registrations
        appRegs = api.get_msgraph_value(f"/applications/", "$expand=owners", msGraphToken)
        if appRegs == None:
            printer.print_error(f"Could not fetch Application Registrations")
        else:
            globalconfig.appRegs = appRegs
        bar()

        # group settings
        groupSettings = api.get_msgraph_value("/groupSettings", {}, msGraphToken)
        if groupSettings == None:
            printer.print_error(f"Could not fetch GroupSettings")
        bar()

        #tenant id
        tenantId = org["id"]
        globalconfig.tenantId = tenantId

        # users
        users = api.get_msgraph_value(
            "/users", 
            {
               "$select": "displayName,id,userPrincipalName,userType,onPremisesSyncEnabled,accountEnabled"
            }, 
            msGraphToken
        )    
        if users == None:
            printer.print_error("Could not fetch users")
        bar()

        # userregistrationdetails
        userRegistrationDetails =  api.get_msgraph_value("/reports/authenticationMethods/userRegistrationDetails", {}, msGraphToken)
        if userRegistrationDetails == None:
            printer.print_error("Could not fetch user MFA methods, no MFA information will be provided!")
            globalconfig.userRegistrationDetails = None
        else:
            globalconfig.userRegistrationDetails = userRegistrationDetails
        bar()

        # directoryRoles
        directoryRoles = api.get_msgraph_value("/directoryRoles", {"$expand": "members"}, msGraphToken)
        if directoryRoles == None:
            printer.print_error("Could not fetch Directory Roles")
        bar()

        # pim assignments
        eligibleAssignments = api.get_msgraph_value(
            "/roleManagement/directory/roleEligibilitySchedules",
            params={ "$expand": "principal,roleDefinition" },
            token=pimToken
        )
        bar()
        activeAssignments = api.get_msgraph_value(
            "/roleManagement/directory/roleAssignmentSchedules",
            params={ "$expand": "principal,roleDefinition" },
            token=pimToken
        )
        bar()
        pimAssignments = None
        if eligibleAssignments == None or activeAssignments == None:
            printer.print_error("Could not fetch PIM assignments")
        else:
            pimAssignments = eligibleAssignments + activeAssignments
        
        # caps
        conditionalAccessPolicies = []
        try:
            allPolicies = api.get_aadgraph_value("/policies", {}, tenantId, aadGraphToken)
            if allPolicies == None:
                printer.print_error("Could not fetch Conditional Access Policies via AAD-Graph, trying MS-Graph instead...")
                conditionalAccessPolicies = api.get_msgraph_value("/identity/conditionalAccess/policies",{},msGraphToken)
                if conditionalAccessPolicies != None and len(conditionalAccessPolicies) == 0:
                    printer.print_info("No Conditional Access Policies")
            else:
                conditionalAccessPolicies = [policy for policy in allPolicies if policy["policyType"]==18] # what are the other policies??
                if len(conditionalAccessPolicies) == 0:
                    printer.print_info("No Conditional Access Policies")
        except Exception as e:
            printer.print_error(f"Could not fetch CAPs: {e}")
        bar()

        # AuthorizationPolicy
        authorizationPolicy = api.get_msgraph("/policies/authorizationPolicy/authorizationPolicy", {}, msGraphToken, "beta")
        if authorizationPolicy == None:
            printer.print_error("Could not fetch Authorization Policy")
        bar()

        #sspr settings
        ssprSettings = api.get_main_iam("PasswordReset/PasswordResetPolicies",{"getPasswordResetEnabledGroup":"true"},mainIamAccessToken)
        if ssprSettings == None:
            printer.print_error("Could not fetch SSPR Settings")
        bar()
        on_premise_integration_settings = api.get_main_iam("PasswordReset/OnPremisesPasswordResetPolicies",{},mainIamAccessToken)
        if on_premise_integration_settings == None:
            printer.print_error("Could not fetch SSPR on-Premises Integration")
        bar()

        # Seamless-SSO settings
        
        ssoSettings = api.get_main_iam("/Directories/GetSeamlessSingleSignOnDomains",{},mainIamAccessToken)
        if ssoSettings == None:
            printer.print_error("Could not fetch Seamless-SSO Settings")
        bar()

        # Administrative Units
        admUnits = api.get_msgraph_value("/directory/administrativeUnits", {}, msGraphToken)
        if admUnits == None:
            printer.print_error("Could not fetch Administrative Units")
        bar()

        # Named Locations
        namedLocations = api.get_msgraph_value("/identity/conditionalAccess/namedLocations", {}, msGraphToken)
        if namedLocations == None:
            printer.print_error("Could not fetch Named Locations")
        bar()

        # Devices
        devices = api.get_msgraph_value("/devices", {"$top": "999"}, msGraphToken)
        if devices == None:
            printer.print_error("Could not fetch Devices")
        bar()

        # users from beta
        usersBeta = api.get_msgraph_value("/users", {}, msGraphToken, "beta")
        if usersBeta == None:
            printer.print_error("Could not fetch Users from beta api")
        bar()

        # subscriptions
        subscriptionsRaw = api.get_arm("/subscriptions", {}, armToken)
        if subscriptionsRaw == None:
            printer.print_error("Could not fetch Subscriptions")
        bar()

        # subscription management policies (Restless Guest Check)
        subscriptionsPolicy = api.get_arm("/providers/Microsoft.Subscription/policies/default", {}, armToken, "2021-01-01-privatepreview")
        bar()

        # policies
        deviceRegistrationPolicy = None
        partnerAccess = None
        crossTenantAccessDefaults = None
        authMethods = None
        if globalargs.policies:
            deviceRegistrationPolicy = api.get_msgraph("/policies/deviceRegistrationPolicy", {}, policyAccessToken, "beta")
            if deviceRegistrationPolicy == None:
                printer.print_error(f"Could not fetch Device Registration Policy")
            bar()
            authMethods = api.get_msgraph("/policies/authenticationmethodspolicy", {}, policyAccessToken, "beta")
            if authMethods == None:
                printer.print_error(f"Could not fetch Authentication Methods")
            bar()
            partnerAccess = api.get_msgraph("/policies/crossTenantAccessPolicy/partners", {"$expand": "identitySynchronization"}, policyAccessToken, "beta") 
            if partnerAccess == None:
                printer.print_error(f"Could not fetch cross-tenant partner access configurations")
            bar()
            crossTenantAccessDefaults = api.get_msgraph("/policies/crossTenantAccessPolicy/default", {}, policyAccessToken, "beta")
            if crossTenantAccessDefaults == None:
                printer.print_error(f"Could not fetch cross-tenant access defaults")
            bar()
        
        # idp and federation
        federationConfig = None
        identityProviders = None
        if globalargs.identity_provider:
            federationConfig = api.get_msgraph_value("/directory/federationConfigurations/graph.samlOrWsFedExternalDomainFederation", {}, idpAccessToken)
            identityProviders = api.get_msgraph_value("/identity/identityProviders",{},idpAccessToken)
            if federationConfig == None:
                printer.print_error(f"Could not fetch Federation Config")
            bar()
            if identityProviders == None:
                printer.print_error(f"Could not fetch Identity Providers")
            bar()

        if globalargs.output_json:
            printer.print_info("Preparing raw JSON for output...")
            
            output.add_json_raw_output("org", org)
            output.add_json_raw_output("groups", groups)
            output.add_json_raw_output("users", users)
            output.add_json_raw_output("servicePrincipals", servicePrincipals)
            output.add_json_raw_output("appRegs", appRegs)
            output.add_json_raw_output("groupSettings", groupSettings)
            output.add_json_raw_output("directoryRoles", directoryRoles)
            output.add_json_raw_output("eligibleAssignments", eligibleAssignments)
            output.add_json_raw_output("activeAssignments", activeAssignments)
            output.add_json_raw_output("userRegistrationDetails", userRegistrationDetails)
            output.add_json_raw_output("conditionalAccessPolicies", conditionalAccessPolicies)
            output.add_json_raw_output("authorizationPolicy", authorizationPolicy)
            output.add_json_raw_output("ssprSettings", ssprSettings)
            output.add_json_raw_output("authMethods", authMethods)
            output.add_json_raw_output("onPremiseIntegrationSettings", on_premise_integration_settings)
            output.add_json_raw_output("seamlessSSO", ssoSettings)
            output.add_json_raw_output("admUnits", admUnits)
            output.add_json_raw_output("namedLocations", namedLocations)
            output.add_json_raw_output("devices", devices)
            output.add_json_raw_output("deviceRegistrationPolicy", deviceRegistrationPolicy)
            output.add_json_raw_output("usersBeta", usersBeta)
            output.add_json_raw_output("subscriptionsRaw", subscriptionsRaw)
            output.add_json_raw_output("subscriptionsPolicy", subscriptionsPolicy)
            output.add_json_raw_output("federationConfig", federationConfig)
            output.add_json_raw_output("identityProviders", identityProviders)
            output.add_json_raw_output("partnerAccess", partnerAccess)
            output.add_json_raw_output("crossTenantAccessDefaults", crossTenantAccessDefaults)
    # https://graph.microsoft.com/v1.0/directory/federationConfigurations/graph.samlOrWsFedExternalDomainFederation
    # https://graph.microsoft.com/v1.0/directory/federationConfigurations - 74658136-14ec-4630-ad9b-26e160ff0fc6
    #https://graph.microsoft.com/beta/identity/identityProvider  - IdentityProvider.ReadWrite.all - 1b730954-1685-4b74-9bfd-dac224a7b894
    



    # Basic Tenant Info
    enum_basic_info(org, groups, servicePrincipals, groupSettings, users, userRegistrationDetails, appRegs, subscriptionsRaw, subscriptionsPolicy, msGraphToken, policyAccessToken)
    
    # General user settings
    enum_user_settings(authorizationPolicy, groupSettings)

    # Device Settings
    enum_device_settings(authorizationPolicy, deviceRegistrationPolicy, conditionalAccessPolicies, msGraphToken)

    # Devices
    enum_devices(devices, msGraphToken)

    # SSPR Settings
    enum_sspr_settings(ssprSettings, on_premise_integration_settings)
    
    # Authentication Methods
    if globalargs.policies:
        domain = helper.decode_jwt(policyAccessToken)["upn"].split("@")[1]
        enum_authentication_methods(authMethods, domain)
        # Cross Tenant Acccess Settings
        enum_cross_tenant_access(partnerAccess, crossTenantAccessDefaults, msGraphToken)
    # Alternatively we could query the reports of used authenticationMethods and guess which methods are therefore enabled.
    # Would NOT need another login:
    # https://graph.microsoft.com/v1.0/reports/authenticationMethods/usersRegisteredByMethod
    
    if globalargs.identity_provider:
        enum_idps(identityProviders, federationConfig)
    
    # Seamless SSO Settings
    enum_seamless_sso(ssoSettings)

    # Dynamic groups
    enum_dynamic_groups(groups, conditionalAccessPolicies)

    # Modifiable groups
    enum_modifiable_groups(groups, conditionalAccessPolicies)

    # Named locations
    enum_named_locations(namedLocations)

    # Conditional Access
    enum_conditional_access(conditionalAccessPolicies)

    # Administrative Units
    enum_administrative_units(admUnits, directoryRoles, pimAssignments, users, msGraphToken)

    # Administrators
    if pimAssignments == None or globalargs.show_directory_roles:
        enum_directory_roles(directoryRoles, msGraphToken)

    # PIM Assignments
    if pimAssignments != None:
        # check if there seem to be role assignments outside of PIM even though PIM is in use...
        #count directory role members
        directory_roles_members = []
        for directory_role in directoryRoles:
            if len(directory_role.get("members")) > 0:
                directory_roles_members.extend(directory_role.get("members"))
    
        # count pim assignments which are not scoped
        active_assignments_directory_scoped = []
        for assignment in activeAssignments:
            if assignment.get("directoryScopeId") == "/":
                active_assignments_directory_scoped.append(assignment)

        assignments_outside_pim = len(active_assignments_directory_scoped) - len(directory_roles_members)
        enum_pim_assignments(users, pimAssignments, msGraphToken, assignments_outside_pim=assignments_outside_pim)

    # API-Permissions
    if servicePrincipals != None:
        enum_app_api_permissions(servicePrincipals, tenantId, msGraphToken)


    # Search principals properties for creds
    search_principal_properties(groups, servicePrincipals, usersBeta)

    if args and globalargs.output_text:
        try:
            globalargs.output_text.write(globalconfig.log_content)
            globalargs.output_text.close()
        except Exception as e:
            printer.print_error(f"Could not write log file with error: {e}")
    
    if args and globalargs.output_json:
        #JSON output is WIP and can be enhanced for better parsing and more preprocessed data
        try:
            cleaned_json_content = helper.remove_circular_refs(globalconfig.json_content)
            dump = json.dumps(cleaned_json_content)
            globalargs.output_json.write(dump)
            globalargs.output_json.close()
        except Exception as e:
            printer.print_error(f"Could not write json file with error: {e}")



if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        printer.print_info('KeyboardInterrupt... Exit now!')
        sys.exit(1)
 
