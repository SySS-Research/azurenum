from azurenum.utils import const, printer
import json

#enum CAPs. should work via aad and msgraph
def enum_conditional_access(conditionalAccessPolicies):
    printer.print_header("Conditional Access Policies")
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
            continue
    # check if  a cap has userAction securityRegister is set to trusted locations and print info
    if registerMfaExternally == True:
        print()
        printer.print_warning(f"{const.RED}Seems like MFA can be registered from anywhere!{const.NC}")
    if registerDeviceCap == False:
        print()
        printer.print_warning(f"{const.RED}Seems like devices can be registered without MFA (Cross-Check with device settings by using -pol argument)!{const.NC}")

