from azurenum.utils import const, printer
import json

#enum CAPs. should work via aad and msgraph
def enum_conditional_access(conditionalAccessPolicies, capEnforcement):
    printer.print_header("Conditional Access Policies")

    # CAP enforcement
    caps_enforced = False
    if capEnforcement != None:
        # printer.print_error("Could not retrieve condional access policies!")
        # return
        # do checks
        LEGACY = "00000000-0000-0000-0000-000000000000"
        ENFORCED = "00000002-0000-0000-c000-000000000000"
        resourceAppId = None

        printer.print_link(f"Entra: https://aka.ms/BaselineScopesSettingsUX")
        try:
            resourceAppId = capEnforcement.get("advancedSettings",{}).get("baselineScopes",{}).get("resourceAppId", None)
        except:
            printer.print_error("Could not parse cap enforcement object")
        if resourceAppId != None:
            if resourceAppId == ENFORCED:
                printer.print_info("CAP enforcement is active!\n")
                caps_enforced = True
            elif resourceAppId == LEGACY:
                printer.print_warning("CAP enforcement is disabled!\n")
                caps_enforced = False
            else:
                printer.print_warning("Custom CAP enforcement!\n")
                caps_enforced = None

    # CAPs
    printer.print_link(f"Portal: {const.AZURE_PORTAL}/?feature.msaljs=false#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies")
    if conditionalAccessPolicies == None:
        printer.print_error("Could not retrieve condional access policies!")
        return
    isAadGraph = True #check if aadGraph is still online
    try:
        test = conditionalAccessPolicies[0]["policyDetail"] #should raise error if aadGraph is offline
    except:
        isAadGraph = False
        
    
    if len(conditionalAccessPolicies) == 0:
        printer.print_info("No Conditional Access Policies were retrieved.")
        return
    
    printer.print_info(f"{len(conditionalAccessPolicies)} Conditional Access Policies found")
    registerMfaExternally = True
    registerDeviceCap = False
    # CAP printing with msgraph and aadgraph compatibility
    # !Cleanup when (if ever?) aadgraph is offline
    for cap in conditionalAccessPolicies:
        displayName = cap["displayName"]
        details = json.loads(cap["policyDetail"][0]) if isAadGraph else cap
        state = details["State"] if isAadGraph else details["state"]
        color = const.RED
        enabledString = "Enabled" if isAadGraph else "enabled"
        reportingString = "Reporting" if isAadGraph else "enabledForReportingButNotEnforced"
        printState = "Disabled"
        if state == enabledString:
            color = const.GREEN
            printState = "Enabled"
        elif state == reportingString:
            color = const.ORANGE
            printState = "Reporting"
        printer.print_info(f"- {color}[{printState}]{const.NC} {const.GREEN}\"{displayName}\"{const.NC}")
        try:
            includedApps = details["Conditions"]["Applications"]["Include"] if isAadGraph else [details["conditions"]["applications"]]
            for app in includedApps:
                acrs = app["Acrs"] if isAadGraph else app["includeUserActions"]
                for acr in acrs:
                    # condition on 'registering MFA'
                    if acr == "urn:user:registersecurityinfo":
                        locationInclude = details["Conditions"]["Locations"]["Include"] if isAadGraph else details["conditions"]["locations"]["includeLocations"]
                        locationExclude = details["Conditions"]["Locations"]["Exclude"] if isAadGraph else details["conditions"]["locations"]["excludeLocations"]
                        if len(locationInclude) > 0 and len(locationExclude) > 0:
                            printer.print_warning("          Policy seems to configure trusted locations for MFA registration")
                            registerMfaExternally = False
                        else:
                            printer.print_warning("          Policy configures MFA registration without use of locations")
                    # condition on 'registering/joining device'
                    elif acr == "urn:user:registerdevice":
                        registerDeviceCap = True
                        locationInclude = details["Conditions"]["Locations"]["Include"] if isAadGraph else details["conditions"]["locations"]["includeLocations"]
                        locationExclude = details["Conditions"]["Locations"]["Exclude"] if isAadGraph else details["conditions"]["locations"]["excludeLocations"]
                        if len(locationInclude) > 0 and len(locationExclude) > 0:
                            printer.print_warning("          Policy seems to configure trusted locations for device registration")
                            registerMfaExternally = False
                        else:
                            printer.print_warning("          Policy configures device registration without use of locations")
        except Exception as e:
            # print(e)
            pass

        # warn if cap targets all resources, excludes some and cap_enforcement is False
        try:
            apps = details["Conditions"]["Applications"]  if isAadGraph else [details["conditions"]["applications"]] 
            includedApps = apps["Include"][0]["Applications"] if isAadGraph else app["includeApplications"] 
            excludedApps = apps["Exclude"][0]["Applications"] if isAadGraph else app["excludeApplications"]
            if "All" in includedApps and len(excludedApps) > 0 and caps_enforced == False:
                printer.print_warning("          Policy targets all resources but excludes some while cap enforcement is disabled - this might be bypassable!")
            elif "All" in includedApps and len(excludedApps) > 0 and caps_enforced == None:
                printer.print_warning("          Policy targets all resources but excludes some while cap enforcement is set to custom resources - this might be bypassable!")
        except Exception as e:
            # print(e)
            pass

    # check if  a cap has userAction securityRegister is set to trusted locations and print info
    if registerMfaExternally == True:
        printer.print_simple("")
        printer.print_warning(f"{const.RED}Seems like MFA can be registered from anywhere!{const.NC}")
    if registerDeviceCap == False:
        printer.print_simple("")
        printer.print_warning(f"{const.RED}Seems like devices can be registered without MFA (Cross-Check with device settings by using -pol argument)!{const.NC}")

