from azurenum.utils import const, printer

# enum password reset options - uses main.iam backend
def enum_sspr_settings(sspr_settings=None, on_premise_integration_settings=None):
    #expects data from get_main_iam("PasswordReset/PasswordResetPolicies",{"getPasswordResetEnabledGroup":"true"},mainIamAccessToken), on_premise_integration_settings = get_main_iam("PasswordReset/OnPremisesPasswordResetPolicies",{},mainIamAccessToken)
    printer.print_header("SSPR Settings")
    printer.print_link(f"Portal: {const.AZURE_PORTAL}/#view/Microsoft_AAD_IAM/PasswordResetMenuBlade")
    
    if sspr_settings == None:
        printer.print_error("Could not fetch SSPR settings")
        return
    # enablementType = 0 -> None/ only admins
    # enablementType = 1 -> selected group
    # enablementType = 2 -> everyone
    match sspr_settings["enablementType"]:
        case 0:
            printer.print_info("SSPR is disabled for users in this tenant")
            return
        case 1:
            printer.print_info(f"SSPR is enabled for group {sspr_settings["passwordResetEnabledGroupName"]} ({sspr_settings["passwordResetEnabledGroupIds"][0]})")
        case 2:
            printer.print_warning("SSPR is enabled for everyone")
        case _:
            printer.print_error("Error while getting SSPR settings.")
    # print warning if sspr is allowed with only one method
    printer.print_warning("[Number of Authentication Methods] required: 1") if sspr_settings["numberOfAuthenticationMethodsRequired"] == 1 else printer.print_info(f"[Number of Authentication Methods] required: {sspr_settings["numberOfAuthenticationMethodsRequired"]}")
    
    printer.print_info("[Users] are notified about password resets") if sspr_settings["notifyUsersOnPasswordReset"] else printer.print_warning("[Users] are not notified about password resets")
    printer.print_info("[Admins] are notified about password resets") if sspr_settings["notifyOnAdminPasswordReset"] else printer.print_warning("[Admins] are not notified about password resets")
    
    print()
    # enumerate on premise integration settings
    if on_premise_integration_settings != None:
        if on_premise_integration_settings["objectId"] != None and on_premise_integration_settings["enablementForTenant"]:
            printer.print_info(f"Integrated with on-Premises with id: {on_premise_integration_settings["objectId"]}")
            printer.print_warning("- Password-Writeback is supported!") if on_premise_integration_settings["passwordWritebackSupported"] else printer.print_info("- Passwordwriteback is not supported!")
            printer.print_warning("- Account-Unlock is supported and enabled!") if on_premise_integration_settings["accountUnlockSupported"] and on_premise_integration_settings["accountUnlockEnabled"] else None
            print()

    # list methods
    printer.print_info("Allowed and Enabled SSPR-Methods:")
    if sspr_settings["emailOptionEnabled"] and sspr_settings["emailOptionAllowed"]:
        printer.print_simple("- [Email]")
    if sspr_settings["mobilePhoneOptionEnabled"] and sspr_settings["mobilePhoneOptionAllowed"]:
        printer.print_simple("- [MobilePhone]")
    if sspr_settings["officePhoneOptionEnabled"] and sspr_settings["officePhoneOptionAllowed"]:
        printer.print_simple("- [OfficePhone]")
    if sspr_settings["mobileAppNotificationEnabled"] and sspr_settings["mobileAppNotificationOptionAllowed"]:
        printer.print_simple("- [MobileApp]")
    if sspr_settings["mobileAppCodeEnabled"] and sspr_settings["mobileAppCodeOptionAllowed"]:
        printer.print_simple("- [MobileAppCode]")
    if sspr_settings["securityQuestionsOptionEnabled"] and sspr_settings["securityQuestionsOptionAllowed"]:
        printer.print_simple(f"- {const.ORANGE}[SecurityQuestions]{const.NC}")
        printer.print_simple(f"    - {sspr_settings["numberOfQuestionsToRegister"]} to register")
        print(f"    - {sspr_settings["numberOfQuestionsToReset"]} to reset")
        if len(sspr_settings["securityQuestions"]):
            print("      - Listing Possible Security Questions...")
            for question in sspr_settings["securityQuestions"]:
                print(f"        - {question["questionText"]}")       
    # if no methods enabled and allowed:                
    if not (sspr_settings["emailOptionEnabled"] and sspr_settings["emailOptionAllowed"] or sspr_settings["mobilePhoneOptionEnabled"] and sspr_settings["mobilePhoneOptionAllowed"] or sspr_settings["officePhoneOptionEnabled"] and sspr_settings["officePhoneOptionAllowed"] or sspr_settings["mobileAppNotificationEnabled"] and sspr_settings["mobileAppNotificationOptionAllowed"] or sspr_settings["mobileAppCodeEnabled"] and sspr_settings["mobileAppCodeOptionAllowed"] or sspr_settings["securityQuestionsOptionEnabled"] and sspr_settings["securityQuestionsOptionAllowed"]):
        printer.print_info("Seems like no methods are enabled AND allowed for SSPR. Maybe they are moved to authentication method in this tenant.")
