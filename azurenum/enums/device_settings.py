from azurenum.utils import const, printer, output, helper
from azurenum.utils.config import globalargs as globalargs
import json

# device settings and device registration    
def enum_device_settings(authorizationPolicy, devicePolicy=None, conditionalAccessPolicies=None, msGraphToken=None):
    printer.print_header("Device Settings")
    printer.print_link(f"Portal: {const.AZURE_PORTAL}/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/DeviceSettings/menuId~/null")
    #printer.print_info("If \"Users may join devices to Azure AD\" is enabled you may be able to create BPRT users, bypass the device quota, and provoke DoS: https://aadinternals.com/post/bprt/")
    jsonDeviceSettings = {}
    # Bitlocker keys policy
    if authorizationPolicy != None:
        allowReadBitlocker = authorizationPolicy["defaultUserRolePermissions"]["allowedToReadBitlockerKeysForOwnedDevice"]
        if allowReadBitlocker == True:
            printer.print_warning("Users can recover Bitlocker Keys of owned devices")
            jsonDeviceSettings["usersCanReadBitlockerKeys"] = True
        else:
            printer.print_info("Users can not recover Bitlocker Keys of owned devices")
            jsonDeviceSettings["usersCanReadBitlockerKeys"] = False
    
    # now using MSGraph instead of AADGraph
    # "https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy"
    # device Policy needs either additional login or BROCI auth
    if devicePolicy != None:
        try:
            if devicePolicy != None and devicePolicy["id"] == "deviceRegistrationPolicy":
                userDeviceQuota = devicePolicy["userDeviceQuota"]
                print()
                printer.print_info(f"Maximum number of devices per user: {userDeviceQuota}")
                jsonDeviceSettings["userDeviceQuota"] = userDeviceQuota


                azureADRegistration = devicePolicy["azureADRegistration"]
                azureADRegistrationType = azureADRegistration["allowedToRegister"]["@odata.type"]
                azureADRegistrationEnforced = not azureADRegistration["isAdminConfigurable"]
                if azureADRegistrationType == "#microsoft.graph.allDeviceRegistrationMembership":
                    if azureADRegistrationEnforced:
                        printer.print_info("Anyone can register devices to Entra")
                    else:
                        printer.print_warning(f"{const.YELLOW}Anyone can register devices to Entra{const.NC}")
                    jsonDeviceSettings["deviceRegistration"] = True
                else:
                    printer.print_info("Device registration is disabled")
                    jsonDeviceSettings["deviceRegistration"] = False

                azureADJoin = devicePolicy["azureADJoin"]
                adJoinType = azureADJoin["allowedToJoin"]["@odata.type"]
                # who is allowed to join devices?
                if adJoinType == "#microsoft.graph.allDeviceRegistrationMembership":
                    printer.print_warning(f"{const.YELLOW}Anyone can join devices to Entra{const.NC}")
                    jsonDeviceSettings["deviceJoinAllowedFor"] = "anyone"
                elif adJoinType == "#microsoft.graph.noDeviceRegistrationMembership":
                    printer.print_info(f"{const.GREEN}No one can join devices to Entra{const.NC}")
                    jsonDeviceSettings["deviceJoinAllowedFor"] = "noone"
                elif adJoinType == "#microsoft.graph.enumeratedDeviceRegistrationMembership":
                    printer.print_info("The following principals are allowed to join devices:")
                    usersResolved = []
                    groupsResolved = []
                    if len(azureADJoin["allowedToJoin"]["users"]) > 0:
                        usersResolved = helper.get_directoryObjects_byIds(ids=azureADJoin["allowedToJoin"]["users"], msGraphToken=msGraphToken)
                    if len(azureADJoin["allowedToJoin"]["groups"]) > 0:
                        groupsResolved = helper.get_directoryObjects_byIds(ids=azureADJoin["allowedToJoin"]["groups"], msGraphToken=msGraphToken)
                    jsonDeviceSettings["deviceJoinAllowedFor"] = usersResolved
                    jsonDeviceSettings["deviceJoinAllowedFor"] += groupsResolved
                    for user in usersResolved:
                        printer.print_simple(f"    - [USER] {user.get("userPrincipalName")}")
                    for group in groupsResolved:
                        printer.print_simple(f"    - [GROUP] {group.get("displayName")}")
                else:
                    printer.print_error("Could not retrieve known device join types.")


                mfaForRegister = devicePolicy["multiFactorAuthConfiguration"]# notRequired
                # cross referencing with conditional access
                if conditionalAccessPolicies != None:
                    deviceRegRestrictedByCap = False
                    isAadGraph = True
                    try:
                        test = conditionalAccessPolicies[0]["policyDetail"]
                    except:
                        isAadGraph = False
                    try:
                        for cap in conditionalAccessPolicies:
                            details = json.loads(cap["policyDetail"][0]) if isAadGraph else cap
                            if isAadGraph:
                                if details["State"] == "Enabled":
                                    includedApps = details["Conditions"]["Applications"]["Include"] if isAadGraph else [details["conditions"]["applications"]]
                                else:
                                    continue
                            elif not isAadGraph:
                                if details["state"] == "enabled":
                                    includedApps = details["Conditions"]["Applications"]["Include"] if isAadGraph else [details["conditions"]["applications"]]
                                else:
                                    continue
                            
                            for app in includedApps:
                                try:
                                    acrs = app["Acrs"] if isAadGraph else app["includeUserActions"]
                                    for acr in acrs:
                                        if acr == "urn:user:registerdevice":
                                            deviceRegRestrictedByCap = True
                                except:
                                    continue
                    except Exception as e:
                        print(f"error in device settings while parsing caps: {e}")
                    if not deviceRegRestrictedByCap:
                        mfaState = f"{const.GREEN}enforced{const.NC}" if mfaForRegister == "required" else f"{const.RED}not enforced{const.NC}"
                    else:
                        mfaState = "handled by a conditional access policy"
                else:
                    mfaState = f"{const.GREEN}enforced{const.NC}" if mfaForRegister == "required" else f"not enforced (Check conditional access!)"
                printer.print_warning(f"MFA for Registering/Joining is {mfaState}!\n")
                jsonDeviceSettings["deviceJoinMfaRestricted"] = True if mfaForRegister=="required" or deviceRegRestrictedByCap else False
                localAdminAfterJoin = azureADJoin["localAdmins"]
                addGlobalAdmAsLocAdm = localAdminAfterJoin["enableGlobalAdmins"]
                printer.print_info("Global Admins are added as local admins on joining a device!") if addGlobalAdmAsLocAdm else printer.print_info("Global Admins are NOT added as local admins on joining a device!")
                addUserAsLocAdm = localAdminAfterJoin["registeringUsers"]
                if addUserAsLocAdm["@odata.type"] == "#microsoft.graph.allDeviceRegistrationMembership":
                    printer.print_info("Joining User is added as local admin")
                elif addUserAsLocAdm["@odata.type"] == "#microsoft.graph.enumeratedDeviceRegistrationMembership":
                    printer.print_info("The following principals are added as local admin when joining device:")
                    
                    if len(addUserAsLocAdm["users"]) > 0:
                        users = helper.get_directoryObjects_byIds(msGraphToken=msGraphToken, ids=addUserAsLocAdm["users"])
                        for user in users:
                            printer.print_simple(f"    - [USER] {user["userPrincipalName"]}")
                    if len(addUserAsLocAdm["groups"]) > 0:
                        groups = helper.get_directoryObjects_byIds(msGraphToken=msGraphToken, ids=addUserAsLocAdm["groups"])
                        for group in groups:
                            printer.print_simple(f"    - [GROUP] {groups["displayName"]} ({group["id"]})")
                print()
                printer.print_info("LAPS for Entra is enabled") if devicePolicy["localAdminPassword"]["isEnabled"] else printer.print_info("LAPS for Entra is disabled")
            else:
                printer.print_error("Could not retrieve deviceRegistrationPolicy!")
        except Exception as e:
            print(f"Error on parsing deviceRegistrationPolicy: {e}")
    elif globalargs.policies:
        printer.print_error("Could not fetch device registration policy!")
    else:
        print()
        printer.print_warning("If you would like to have more information, use --policies flag.")
    output.add_json_output(const.DEVICE_SETTINGS, jsonDeviceSettings)
