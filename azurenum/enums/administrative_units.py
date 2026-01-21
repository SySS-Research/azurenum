from azurenum.utils import const, api, printer, helper

def enum_administrative_units(admUnits, directoryRoles, pimAssignments, users, msGraphToken):
    printer.print_header("Administrative Units")
    printer.print_link(f"Portal: {const.AZURE_PORTAL}/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/AdminUnit")
    if admUnits == None:
        printer.print_error("Could not fetch Administrative Units")
        return
    if directoryRoles == None:
        printer.print_error("Could not fetch directory roles")
        return
    admUnitsNum = len(admUnits)
    if admUnitsNum == 0:
        printer.print_info("No Administrative Units found")
        return
    
    printer.print_info(f"{admUnitsNum} Administrative Units found")
    for unit in admUnits:
        displayName = unit["displayName"]
        admUnitId = unit["id"]
        membershipType = "Dynamic" if unit["membershipType"] == "Dynamic" else "Assigned"
        membershipRule = unit["membershipRule"] if unit["membershipRule"] != None else ""
        isRestricted = f"{const.YELLOW}[Restricted management]{const.NC}" if unit["isMemberManagementRestricted"] else ""
        # Get Admin Roles (restricted to this administrative unit)
        admRoles = api.get_msgraph_value(f"/directory/administrativeUnits/{admUnitId}/scopedRoleMembers", {}, msGraphToken)
        ruleText = f": {membershipRule}" if membershipRule != "" else ""
        printer.print_info(f"- {const.GREEN}[{membershipType}] {displayName}{const.NC} {isRestricted} {ruleText}")
        if pimAssignments != None:
            assignments = [assignment for assignment in pimAssignments if assignment["directoryScopeId"] == f"/administrativeUnits/{admUnitId}"]

            for assignment in assignments:
                principalId = assignment["principal"]["id"]
                displayName = assignment["principal"]["displayName"]
                type = assignment["principal"]["@odata.type"]

                # Parameters will be set for user objects
                lacksMfa = ""
                synced = ""
                roleName = assignment.get("roleDefinition")["displayName"]
                if type == "#microsoft.graph.user":
                    principalId = assignment["principal"]["userPrincipalName"] # for users, show UPN instead of ID 

                    # Check whether synced & no MFA methods
                    userObject = next((user for user in users if user["userPrincipalName"] == principalId), None)
                    # check mfa
                    userHasMfa = helper.hasUserMFA(principalId)

                    # include account state on type
                    active = "" if userObject["accountEnabled"] else " (DISABLED)"
                    friendlyType = f"USER{const.YELLOW}{active}{const.NC}"

                    if userHasMfa:
                        lacksMfa = "" 
                    elif userHasMfa == None:
                        lacksMfa = " (MFA unknown)"
                    else: 
                        lacksMfa = f" {const.ORANGE}(No MFA Methods!){const.NC}"
                    # check synced
                    if userObject == None:
                        synced = f" {const.RED}(user not found!){const.NC}"
                    else:
                        synced = f" {const.ORANGE}(synced!){const.NC}" if userObject["onPremisesSyncEnabled"] else ""
                elif type == "#microsoft.graph.group":
                    friendlyType = "GROUP" if assignment["principal"]["membershipRule"] is None else f"GROUP {const.YELLOW}(Dynamic!){const.NC}" # -- Should never appear!
                    #check synced
                    synced = f" {const.ORANGE}(synced!){const.NC}" if assignment["principal"]["onPremisesSyncEnabled"] else ""
                elif type == "#microsoft.graph.servicePrincipal":
                    friendlyType = "SERVICE_PRINCIPAL"
                else:
                    friendlyType = "UNKNOWN_TYPE"

                isPermanent = f"{const.RED}[Permanent]{const.NC}" if assignment["scheduleInfo"]["expiration"]["type"] == "noExpiration" else ""
                assignmentState = "Active" if "assignmentType" in assignment else "Eligible"
                stateText = f"{const.GREEN}[{assignmentState}]{const.NC}" if assignmentState == "Active" else f"{const.CYAN}[{assignmentState}]{const.NC}"
                printer.print_simple(f"- [{friendlyType}] {principalId} ({displayName}) has role [{roleName}] {isPermanent}{stateText}{synced}{lacksMfa}")
        elif admRoles != None:
            for admRole in admRoles:
                displayName = admRole["roleMemberInfo"]["displayName"]
                roleId = admRole["roleId"]
                roleName = next((role["displayName"] for role in directoryRoles if role["id"] == roleId), None)
                # print(roleId)
                printer.print_info(f"  - {displayName} has role [{roleName}]")
