from urllib.parse import quote
from azurenum.utils import const, printer, helper

def enum_cross_tenant_access(settings, defaultsettings, msGraphToken):
#    print(settings['value'])
    printer.print_header("Cross Tenant Access Settings")
    printer.print_link("Portal: https://portal.azure.com/#view/Microsoft_AAD_IAM/CompanyRelationshipsMenuBlade/~/CrossTenantAccessSettings")
    
    # Default settings
    deftrust= defaultsettings["inboundTrust"]
    if deftrust["isMfaAccepted"]:
        printer.print_warning("MFA is trusted from external domains")
    else: 
        printer.print_info("MFA is not trusted from external domains")
    if deftrust["isCompliantDeviceAccepted"]:
        printer.print_warning("Compliant devices are trusted from external domains")
    else: 
        printer.print_info("Compliant devices are not trusted from external domains")
    if deftrust["isHybridAzureADJoinedDeviceAccepted"]:
        printer.print_warning("Hybrid devices are trusted from external domains")
    else: 
        printer.print_info("Hybrid devices are not trusted from external domains")
    if deftrust["isCompliantNetworkAccepted"]:
        printer.print_warning("Networks are trusted from external domains (Unclear what that actually means so be careful)")
    else: 
        printer.print_info("Networks are not trusted from external domains")


    # tenant restriction are only evaluated if GSA is used. do not include in output
    # tenant_restrictions=defaultsettings["tenantRestrictions"]
    # if tenant_restrictions["usersAndGroups"]["accessType"] != "blocked" or tenant_restrictions["applications"]["accessType"] != "blocked":
    #     printer.print_warning("- External Access Allowed for:")
    # else:
    #     printer.print_info("- External access is blocked!")
    # # users and groups
    # if tenant_restrictions["usersAndGroups"]["accessType"] != "blocked":
    #     for user in tenant_restrictions["usersAndGroups"]["targets"]:
    #          printer.print_warning(f"  - [{user["targetType"]}] {const.RED}{user["target"]}{const.NC}")
    # # apps
    # if tenant_restrictions["applications"]["accessType"] != "blocked":
    #     for app in tenant_restrictions["applications"]["targets"]:
    #          printer.print_warning(f"  - [{app["targetType"]}] {const.RED}{app["target"]}{const.NC}")

    print()

    # Partner Specific Configs
    printer.print_info("Partner Specific Configurations")

    for partner in settings['value']:
        tenant_info = helper.get_tenant_info_by_id(partner["tenantId"],msGraphToken)
        printer.print_info(f"- {tenant_info["displayName"]} ({tenant_info["defaultDomainName"]})")
                
        # Inbound Access Settings
        printer.print_link(f"    Portal: https://portal.azure.com/#view/Microsoft_AAD_IAM/InboundAccessSettings.ReactView/name/{quote(tenant_info["displayName"])}/id/{partner["tenantId"]}")
        if partner["inboundTrust"] != None:
            claims = [
                ("MFA", partner["inboundTrust"]["isMfaAccepted"]),
                ("compliant devices", partner["inboundTrust"]["isCompliantDeviceAccepted"]),
                ("hybrid devices", partner["inboundTrust"]["isHybridAzureADJoinedDeviceAccepted"]),
            ]
            trusted_claims = [claim for claim, enabled in claims if enabled]
            if trusted_claims:
                printer.print_warning(f"    Trusted inbound access claims: {const.YELLOW}" + ", ".join(trusted_claims)+ f"{const.NC}")
            else:
                printer.print_info(f"    Partner inbound access trust settings are set to {const.GREEN}block all claims{const.NC}")
        else:
            printer.print_info(f"    Partner inbound access trust settings are set to {const.GREEN}default{const.NC}")

        # B2B Direct Connect Inbound (allows external users to access shared teams channels without being invited as a guest) - currently rather uninteresting
        # if partner["b2bDirectConnectInbound"] != None:
        #     # printer.print_warning("    Non-default B2B Direct Connect settings")
        #     b2b_direct_connect_inbound = partner["b2bDirectConnectInbound"]
                        
        #     if b2b_direct_connect_inbound["usersAndGroups"]["accessType"] != "blocked" or b2b_direct_connect_inbound["applications"]["accessType"] != "blocked":
        #         printer.print_warning("    B2B Direct Connect allowed for:")
        #     else:
        #         printer.print_info("    B2B Direct Connect blocked!")
        #     # users and groups with b2b direct connect access
        #     if b2b_direct_connect_inbound["usersAndGroups"]["accessType"] != "blocked":
        #         for user in b2b_direct_connect_inbound["usersAndGroups"]["targets"]:
        #             printer.print_warning(f"    - [{user["targetType"]}] {const.RED}{user["target"]}{const.NC}")          
        #     if b2b_direct_connect_inbound["applications"]["accessType"] != "blocked":
        #         # applications with b2b direct connect access
        #         for app in b2b_direct_connect_inbound["applications"]["targets"]:
        #             printer.print_warning(f"    - [{app["targetType"]}] {const.RED}{app["target"]}{const.NC}")
            
        #     #{'usersAndGroups': {'accessType': 'allowed', 'targets': [{'target': 'AllUsers', 'targetType': 'user'}]}, 'applications': {'accessType': 'allowed', 'targets': [{'target': 'AllApplications', 'targetType': 'application'}]}}
        # else:
        #     printer.print_info(f"    B2B direct connect settings are set to {const.YELLOW}default{const.NC}")
        
        # # Tenant Restrictions - only work if GSA is used - do not yet include in output
        # printer.print_link(f"    Portal: https://portal.azure.com/#view/Microsoft_AAD_IAM/TenantRestrictions.ReactView/name/{quote(tenant_info["displayName"])}/id/{partner["tenantId"]}")
        # if partner["tenantRestrictions"] != None:
        #     tenant_restrictions=partner["tenantRestrictions"]
        #     if tenant_restrictions["usersAndGroups"]["accessType"] != "blocked" or tenant_restrictions["applications"]["accessType"] != "blocked":
        #         printer.print_warning("    External Access Allowed for:")
        #     else:
        #         printer.print_info("    External access is blocked!")
        #     # users and groups
        #     if tenant_restrictions["usersAndGroups"]["accessType"] != "blocked":
        #         for user in tenant_restrictions["usersAndGroups"]["targets"]:
        #              printer.print_warning(f"    - [{user["targetType"]}] {const.RED}{user["target"]}{const.NC}")
        #     # apps
        #     if tenant_restrictions["applications"]["accessType"] != "blocked":
        #         for app in tenant_restrictions["applications"]["targets"]:
        #              printer.print_warning(f"    - [{app["targetType"]}] {const.RED}{app["target"]}{const.NC}")
        # else:
        #     printer.print_info(f"    Partner tenant restrictions are set to {const.YELLOW}default{const.NC}")

        # Cross-Tenant Sync - identitySynchronization key only exists if access was once allowed. - only print if sync is allowed for either groups or users
        if partner.get("identitySynchronization") != None:
            identity_sync = partner.get("identitySynchronization")
            # printer.print_warning("Cross-Tenant Synchronization Settings are set!")
            if identity_sync["groupSyncInbound"]["isSyncAllowed"] == True and identity_sync["userSyncInbound"]["isSyncAllowed"] == True:
                printer.print_warning("    User and group synchronisation from this partner into your tenant is allowed!")
            elif identity_sync["groupSyncInbound"]["isSyncAllowed"] == True:
                printer.print_warning("    Group synchronization from this partner into your tenant is allowed!")
            elif identity_sync["userSyncInbound"]["isSyncAllowed"] == True:
                printer.print_warning("    User synchronization from this partner into your tenant is allowed!")


