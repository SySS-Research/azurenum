from azurenum.utils import const, api,  printer, output
from datetime import datetime

#enums org data, application overview, guest overview, MFA overview, subscription overview, security default settings
def enum_basic_info(org, groups, servicePrincipals, groupSettings, users, userRegistrationDetails, appRegistrations, subscriptionsRaw, subscriptionsPolicy, msGraphToken, policyAccessToken=None):
    jsonBasicInfo = {}
    jsonGuestInfo = {}
    jsonBasicInfo["tenantId"]=tenantId = org["id"]
    # Object quota
    objNum = org["directorySizeQuota"]["used"]
    objLimit = org["directorySizeQuota"]["total"]
    displayName = org["displayName"]
    verifiedDomains = org["verifiedDomains"]
    defaultDomain = "Error on querying default domain"
    for domain in verifiedDomains:
        if domain["isDefault"] == True:
            defaultDomain = f"{domain["name"]} ({domain["type"]})"
    onPremisesSyncEnabled = org["onPremisesSyncEnabled"]
    if onPremisesSyncEnabled is None:
        onPremisesSyncEnabled = "Disabled"
    else:
        onPremisesSyncEnabled = "Enabled"
    jsonBasicInfo["onPremisesSyncEnabled"]=onPremisesSyncEnabled
    # Licenses
    aadLicenses = [plan["servicePlanId"] for plan in org["assignedPlans"] if plan["capabilityStatus"] == "Enabled" and plan["service"] == "AADPremiumService"]
    if const.AAD_PREMIUM_P2 in aadLicenses:
        aadPlan = "Microsoft Entra ID P2"
    elif const.AAD_PREMIUM_P1 in aadLicenses:
        aadPlan = "Microsoft Entra ID P1"
    else:
        aadPlan = "Microsoft Entra ID Free"
    jsonBasicInfo["license"]=aadPlan
    if users != None:
        userNum = len(users)
        guestNum = len([user for user in users if user["userType"] == "Guest"])
        guestPercent = round(guestNum / userNum * 100, 2)        
        pendingInvitations = api.get_msgraph_value(
            "/users/",
            {
                "$select":"userPrincipalName,externalUserState,createdDateTime",
                "$filter":"externalUserState eq 'PendingAcceptance'"
            },
            msGraphToken
        )
        if pendingInvitations != None:
            pendingInvitationsNum = len(pendingInvitations)
        else:
            pendingInvitationsNum = "Could not retrieve pending invitations!"
        # Calculate # of orphaned Accounts
        current_datetime = datetime.now() # get the current datetime in UTC timezone        
        jsonGuestInfo["invitationsSinceLarger90"]=invitationsSinceLarger90 = 0
        jsonGuestInfo["invitationsSinceLarger180"]=invitationsSinceLarger180 = 0
        jsonGuestInfo["invitationsSinceLarger365"]=invitationsSinceLarger365 = 0
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
        jsonGuestInfo["noSignInLarger90"]=noSignInLarger90 = 0
        jsonGuestInfo["noSignInLarger180"]=noSignInLarger180 = 0
        jsonGuestInfo["noSignInLarger365"]=noSignInLarger365 = 0
        acceptedGuests = api.get_msgraph_value(
            "/users/",
            {
                "$select": "userPrincipalName,externalUserState,signInActivity",
                "$filter": "externalUserState eq 'Accepted'"
             },
             msGraphToken
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
        modifiableGroups = [group for group in groups if group["visibility"] == "Public" and group["membershipRule"] is None]
        modifiableGroupsNum = len(modifiableGroups)
    if servicePrincipals != None:
        nativeServicePrincipals = [spn for spn in servicePrincipals if spn["appOwnerOrganizationId"] == tenantId]
        nativeServicePrincipalsNum = len(nativeServicePrincipals)
        servicePrincipalNum = len(servicePrincipals)
    
    if appRegistrations == None:
        printer.print_error("Could not fetch App Registrations")
    
    if subscriptionsRaw == None:
        printer.print_error("Could not fetch subscriptions")
    else:
        subscriptions = subscriptionsRaw["value"]

    # MFA Methods per User
    if userRegistrationDetails != None:
        usersWithoutMfa = [userRegistrationDetail for userRegistrationDetail in userRegistrationDetails if not userRegistrationDetail["isMfaCapable"]]
        usersWithoutMfaNum = len(usersWithoutMfa)
        mfaPercent = round(usersWithoutMfaNum / userNum * 100, 2)
        jsonBasicInfo["usersWithNoMFA"]=f"{usersWithoutMfaNum}/{userNum} ({mfaPercent} %)"
    
    jsonBasicInfo["tenantName"]=displayName
    jsonBasicInfo["defaultDomain"] = defaultDomain.split(" ")[0]
    printer.print_header("Basic information")

    printer.print_info(f"TenantID: {tenantId}")
    printer.print_info(f"License: {aadPlan}")
    printer.print_info(f"Size quota: {objNum}/{objLimit}")
    printer.print_info(f"Display name: {displayName}")
    printer.print_info(f"Default domain: {defaultDomain}")
    printer.print_info(f"On Premises Sync: {onPremisesSyncEnabled}") if onPremisesSyncEnabled != "Enabled" else printer.print_warning(f"On Premises Sync: {onPremisesSyncEnabled}")
    if users != None:
        printer.print_info(f"Users: {userNum}")
        printer.print_info(f"Guest Users: {guestNum}/{userNum} ({guestPercent} %)")
        jsonGuestInfo["guestCount"] = f"{guestNum}/{userNum} ({guestPercent} %)"
        printer.print_info(f"Pending invitations: {pendingInvitationsNum}")
        if invitationsSinceLarger90 > 0:
            printer.print_warning(f"Pending invitations waiting for more than 90 days: {invitationsSinceLarger90}")
            jsonGuestInfo["invitationsSinceLarger90"] = invitationsSinceLarger90
        if invitationsSinceLarger180 > 0:
            printer.print_warning(f"Pending invitations waiting for more than 180 days: {invitationsSinceLarger180}")
            jsonGuestInfo["invitationsSinceLarger180"] = invitationsSinceLarger180
        if invitationsSinceLarger365 > 0:
            printer.print_warning(f"Pending invitations waiting for more than 365 days: {invitationsSinceLarger365}")
            jsonGuestInfo["invitationsSinceLarger365"] = invitationsSinceLarger365
        if acceptedGuests != None:
            if noSignInLarger90 > 0:
                printer.print_warning(f"Guests with no signin for more than 90 days: {noSignInLarger90}")
                jsonGuestInfo["noSignInLarger90"] = noSignInLarger90
            if noSignInLarger180 > 0:
                printer.print_warning(f"Guests with no signin for more than 180 days: {noSignInLarger180}")
                jsonGuestInfo["noSignInLarger180"] = noSignInLarger180
            if noSignInLarger365 > 0:
                printer.print_warning(f"Guests with no signin for more than 365 days: {noSignInLarger365}")
                jsonGuestInfo["noSignInLarger365"] = noSignInLarger365
    if userRegistrationDetails != None:
        printer.print_warning(f"Users with no MFA methods: {usersWithoutMfaNum}/{userNum} ({mfaPercent} %)") if mfaPercent > 20 else printer.print_info(f"Users with no MFA methods: {usersWithoutMfaNum}/{userNum} ({mfaPercent} %)")
    if groups != None:
        printer.print_info(f"Groups: {groupNum}")
        if modifiableGroupsNum > 0:
            printer.print_warning(f"Modifiable groups: {modifiableGroupsNum} (Get them with `az ad group list | jq '.[] | select(.visibility == \"Public\") | select(.membershipRule == null).displayName'`)")
        else:
            printer.print_info(f"Modifiable groups: {modifiableGroupsNum} (Get them with `az ad group list | jq '.[] | select(.visibility == \"Public\") | select(.membershipRule == null).displayName'`)")
    if servicePrincipals != None:
        printer.print_info(f"Service Principals: {servicePrincipalNum} (aka. \"Enterprise applications\")")
        printer.print_info(f"Service Principals with AppRegs in this tenant: {nativeServicePrincipalsNum}") 
        jsonBasicInfo["internalServicePrincipalCount"]=nativeServicePrincipalsNum
    if appRegistrations != None:
        printer.print_info(f"Application Definitions: {len(appRegistrations)} (aka. \"App registrations\")")
    if subscriptionsRaw != None:
        printer.print_info(f"Subscriptions: {len(subscriptions)}") if len(subscriptions) == 0 else printer.print_warning(f"Subscriptions: {len(subscriptions)}")
        jsonBasicInfo["subscriptionsCount"]=len(subscriptions)
        for subscription in subscriptions:
            subName = subscription["displayName"]
            printer.print_simple(f"    - {subName}")
    jsonBasicInfo["restlessGuestExploitation"]="unknown"
    if subscriptionsPolicy != None:
        if subscriptionsPolicy["properties"]["policyId"] == "ad91b450-790a-4c8c-b8fd-b76926206154": # default policy
            jsonBasicInfo["restlessGuestExploitation"]="not possible"
            if subscriptionsPolicy["properties"]["blockSubscriptionsIntoTenant"] == False:
                printer.print_warning("Subscription Policy allows for external subscriptions")
                printer.print_warning("This might enable \"Restless Guests\" exploitation:")
                printer.print_link("https://www.beyondtrust.com/blog/entry/restless-guests")
                jsonBasicInfo["restlessGuestExploitation"]="possible"
    printer.print_simple("")

    # LockoutPolicy
    if groupSettings != None:
        passwdRuleSettings = next((setting for setting in groupSettings if setting["displayName"] =="Password Rule Settings"), None)
        lockoutDurationSeconds = 60 # default
        lockoutThreshold = 10 # default
        if passwdRuleSettings != None:
            lockoutDurationSeconds = next((val["value"] for val in passwdRuleSettings["values"] if val["name"] == "LockoutDurationInSeconds"),None)
            lockoutThreshold = next((val["value"] for val in passwdRuleSettings["values"] if val["name"] == "LockoutThreshold"),None)
        printer.print_info(f"Lockout Threshold: {lockoutThreshold}")
        printer.print_info(f"Lockout Duration Seconds: {lockoutDurationSeconds}")
        printer.print_simple("")

    # Security Defaults
    # Following command should get them
    # az rest --method get --url "{const.MS_GRAPH_API}/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
    # also here: https://main.iam.ad.ext.azure.com/api/SecurityDefaults/GetSecurityDefaultStatus
    jsonBasicInfo["securityDefaults"]="unknown"
    if policyAccessToken != None:
        secDefaults = api.get_msgraph("/policies/identitySecurityDefaultsEnforcementPolicy", {}, policyAccessToken)
        if secDefaults["isEnabled"]:
            printer.print_warning("Security Defaults are enabled!") 
            jsonBasicInfo["securityDefaults"]="enabled"
        else:
            printer.print_info("Security Defaults are disabled")
            jsonBasicInfo["securityDefaults"]="disabled"
    else:
        printer.print_info(f"Check if \"Security Defaults\" are enabled: {const.AZURE_PORTAL}/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Properties")
        jsonBasicInfo["securityDefaults"]="unknown"
    output.add_json_output(const.BASIC_INFO, jsonBasicInfo)
    output.add_json_output(const.GUEST_INFO, jsonGuestInfo)

