from azurenum.utils import const, printer, helper, output

# enum active administrative roles. Only called if PIM is not in use or --show-directory-roles is set
def enum_directory_roles(directoryRoles, msGraphToken):
    printer.print_header("Administrative Roles")
    if directoryRoles == None:
        printer.print_error("Could not fetch administrative roles")
        return
    for directoryRole in directoryRoles:
        memberCount = len(directoryRole["members"])
        if memberCount == 0:
            continue
        roleName = directoryRole["displayName"]
        principalsInRole = directoryRole["members"]
        printer.print_info(f"{roleName}: {len(principalsInRole)}")
        for principal in principalsInRole:
            displayName = principal["displayName"]
            principalId = principal["id"]
            enrichedList = None
            # enriching principal with further information for json output
            enrichedPrincipal = principal
            enrichedPrincipal["AzurEnum-EntraRole"] = roleName
            if principal["@odata.type"] == "#microsoft.graph.group":
                synced = ""
                if principal["onPremisesSyncEnabled"]:
                    output.add_json_output(f"{const.DIRECTORY_ROLES}-{const.SYNCED}", enrichedPrincipal)
                    synced = f"{const.ORANGE}(synced!){const.NC}"
                printer.print_simple(f"- [GROUP] {principalId} ({displayName}) {synced}")
                enrichedList = helper.gather_nesting([principal], msGraphToken=msGraphToken)
            elif principal["@odata.type"] == "#microsoft.graph.user":
                userPrincipalName = principal["userPrincipalName"]
                userHasMfa = helper.hasUserMFA(userPrincipalName)
                lacksMfa = ""
                if userHasMfa == None:
                    lacksMfa = " (MFA unknown)"
                elif not userHasMfa:
                    lacksMfa = f" {const.ORANGE}(No MFA Methods!){const.NC}"
                    output.add_json_output(f"{const.DIRECTORY_ROLES}-{const.NO_MFA}", enrichedPrincipal)
                synced = ""
                if principal["onPremisesSyncEnabled"]:
                    synced = f" {const.ORANGE}(synced!){const.NC}"
                    output.add_json_output(f"{const.DIRECTORY_ROLES}-{const.SYNCED}", enrichedPrincipal)
                active = "" if principal["accountEnabled"] else f" {const.YELLOW}(DISABLED){const.NC}"
                printer.print_simple(f"- [USER{active}] {userPrincipalName} ({displayName}){synced}{lacksMfa}")
            elif principal["@odata.type"] == "#microsoft.graph.servicePrincipal":
                printer.print_simple(f"- [SERVICE_PRINCIPAL] {principalId} ({displayName})")
                output.add_json_output(const.PRIVILEGED_APPLICATIONS,enrichedPrincipal)
                enrichedList = helper.gather_nesting([principal], msGraphToken=msGraphToken)
            else:
                principalType = principal["@odata.type"]
                printer.print_error(f"Unknown principal type: {principalType}")
            if principal["@odata.type"] == "#microsoft.graph.group" or  principal["@odata.type"] == "#microsoft.graph.servicePrincipal":
                helper.enum_nested_lists(enrichedList, jsonKey=const.DIRECTORY_ROLES)
    return directoryRoles
