from azurenum.utils import const, printer, output, api

# enum app consent, user permission, guest invitation policy and guest permissions
def enum_user_settings(authorizationPolicy, groupSettings):
    jsonUserSettings = {}
    printer.print_header("General user settings")
    # App Consent Policy
    if authorizationPolicy != None:
        # https://portal.azure.com/?feature.msaljs=false#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/UserSettings
        grantPolicies = authorizationPolicy["permissionGrantPolicyIdsAssignedToDefaultUserRole"] 
        
        printer.print_link(f"Portal: {const.AZURE_PORTAL}/?feature.msaljs=false#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/UserSettings")   
        if "ManagePermissionGrantsForSelf.microsoft-user-default-legacy" in grantPolicies:
            printer.print_warning("Allow user consent for apps")
            jsonUserSettings["userConsent"] = True
        elif "ManagePermissionGrantsForSelf.microsoft-user-default-low" in grantPolicies:
            printer.print_warning("Allow user consent for apps from verified publishers, for selected permissions")
            jsonUserSettings["userConsent"] = "restricted"
        else:
            printer.print_info("Do not allow user consent")
            jsonUserSettings["userConsent"] = False
    
    # App consent group settings
    if groupSettings != None:
        consentPolicySettings = next((setting for setting in groupSettings if setting["displayName"] == "Consent Policy Settings"), None)
        enableAdminConsentRequests:bool = False # default, https://portal.azure.com/?feature.msaljs=false#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/AdminConsentSettings
        # blockUserConsentForRiskyApps = "false" # ?
        if consentPolicySettings != None:
            enableAdminConsentRequests = next((val["value"] for val in consentPolicySettings["values"] if val["name"] == "EnableAdminConsentRequests"),None)
            #blockUserConsentForRiskyApps = consentPolicySettings["BlockUserConsentForRiskyApps"] ?
        printer.print_link(f"Portal: {const.AZURE_PORTAL}/?feature.msaljs=false#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/AdminConsentSettings")
        #printer.print_info(f"Block user consent for risky apps: {blockUserConsentForRiskyApps}") ?
        if enableAdminConsentRequests == True:  # == True or enableAdminConsentRequests.lower() == "true":
            printer.print_warning("Users can request admin consent to apps they are unable to consent to!\n")
            jsonUserSettings["requestAdminConsent"] = True
        elif enableAdminConsentRequests == False:
            printer.print_info("Users can NOT request admin consent to apps they are unable to consent to\n")
            jsonUserSettings["requestAdminConsent"] = False
    if authorizationPolicy != None:
        allowInvitesFrom = authorizationPolicy["allowInvitesFrom"]
        guestUserRole = authorizationPolicy["guestUserRoleId"]
        userCanReadOtherUsers = authorizationPolicy["defaultUserRolePermissions"]["allowedToReadOtherUsers"]

        # Some security settings are just not visible in the Portal, they can be read/set over the Graph API though
        printer.print_link("Portal: NOT visible in the Portal!")
        if userCanReadOtherUsers == True:
            printer.print_warning("Users can read other users information (You can actually block this with the Graph API!)")
        else:
            printer.print_info("Users can not read other users information")
        printer.print_simple("")

        printer.print_link(f"Portal: {const.AZURE_PORTAL}/?feature.msaljs=false#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/UserSettings")
        # create apps
        allowCreateApps = authorizationPolicy["defaultUserRolePermissions"]["allowedToCreateApps"]
        if allowCreateApps == True:
            printer.print_warning("Users can register applications")
            jsonUserSettings["usersCanRegisterApps"] = True
        else:
            printer.print_info("Users can not register applications")
            jsonUserSettings["usersCanRegisterApps"] = False
        # create tenants
        allowCreateTenants = authorizationPolicy["defaultUserRolePermissions"]["allowedToCreateTenants"]
        if allowCreateTenants == True:
            printer.print_warning("Users can create tenants")
            jsonUserSettings["usersCanCreateTenants"] = True
        else:
            printer.print_info("Users can not create tenants")
            jsonUserSettings["usersCanCreateTenants"] = False
       
        printer.print_simple("")
        printer.print_link(f"Portal: {const.AZURE_PORTAL}/?feature.msaljs=false#view/Microsoft_AAD_IAM/AllowlistPolicyBlade")
        # Invitation Policy setting

        jsonUserSettings["allowGuestInvitesFrom"] = allowInvitesFrom
        if allowInvitesFrom == "adminsGuestInvitersAndAllMembers":
            printer.print_warning("Member users and users assigned to specific admin roles can invite guest users including guests with member permissions")
        elif allowInvitesFrom == "everyone": # default
            printer.print_warning("Anyone in the organization can invite guest users including guests and non-admins (most inclusive)")
        elif allowInvitesFrom == "adminsAndGuestInviters":
            printer.print_info("Only users assigned to specific admin roles can invite guest users")
        elif allowInvitesFrom == "none":
            printer.print_info("No one in the organization can invite guest users including admins (most restrictive)")
        else:
            printer.print_error(f"Unknown Guest Invite Policy: {allowInvitesFrom}")

        # Guest User permissions
        if guestUserRole == const.GUEST_ROLE_USER:
            printer.print_warning("Guest users have the same access as members (most inclusive)")
            jsonUserSettings["guestsRole"] = f"{const.GUEST_ROLE_USER}"
        elif guestUserRole == const.GUEST_ROLE_GUEST:
            printer.print_warning("Guest users have limited access to properties and memberships of directory objects")
            jsonUserSettings["guestsRole"] = f"{const.GUEST_ROLE_GUEST}"
        elif guestUserRole == const.GUEST_ROLE_RESTRICTED:
            printer.print_info("Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)")
            jsonUserSettings["guestsRole"] = f"{const.GUEST_ROLE_RESTRICTED}"
        else:
            printer.print_error(f"Unknown Guest Role ID: {guestUserRole}")
      
    # Group Creation settings
    if groupSettings != None:
        groupUnifiedSettings = next((setting for setting in groupSettings if setting["templateId"] == const.GROUP_UNIFIED_TEMPLATE_ID), None)
        enableAdGroupCreation = True # default, https://portal.azure.com/?feature.msaljs=false#view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/General
        if groupUnifiedSettings != None:
            enableAdGroupCreation = next((val["value"] for val in groupUnifiedSettings["values"] if val["name"] == "EnableGroupCreation"),None)
        allowedToCreateSecurityGroups = authorizationPolicy["defaultUserRolePermissions"]["allowedToCreateSecurityGroups"] # https://portal.azure.com/?feature.msaljs=false#view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/General
        printer.print_simple("")
        printer.print_link(f"Portal: {const.AZURE_PORTAL}/?feature.msaljs=false#view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/General")
        # create entra security groups
        if allowedToCreateSecurityGroups == True:
            printer.print_warning("Users can create security groups")
            jsonUserSettings["usersCanCreateSecurityGroups"] = True
        else:
            printer.print_info("Users can not create security groups")
            jsonUserSettings["usersCanCreateSecurityGroups"] = False
        # create M365 groups
        if enableAdGroupCreation == True:
            printer.print_warning("Users can create m365 groups\n")
            jsonUserSettings["usersCanCreateM365Groups"] = True
        else:
            printer.print_info("Users can not create m365 groups\n")
            jsonUserSettings["usersCanCreateM365Groups"] = False
        
    output.add_json_output(const.USER_SETTINGS, jsonUserSettings)

