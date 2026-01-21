from azurenum.utils import const, printer, helper

# check modifiable groups for cap relevancy and approleassignments
def enum_modifiable_groups(groups, conditionalAccessPolicies):
    printer.print_header("Public Groups")
    modifiableGroups = []
    if groups != None and len(groups) > 0:
        modifiableGroups = [group for group in groups if group["visibility"] == "Public" and group["membershipRule"] is None]
    printer.print_info(f"{len(modifiableGroups)} public groups found")
    for group in modifiableGroups:
        displayName = group["displayName"]
        groupType = "Security"
        if "Unified" in group["groupTypes"]:
            groupType = "m365"
        #check if group has approle assignments
        hasAppRoleAssignments = f"{const.YELLOW} (Has AppRoleAssignments){const.NC}" if len(group["appRoleAssignments"]) > 0 else ""
        capRelevant = f"{const.YELLOW} (CAP Relevant!){const.NC}" if helper.check_cap_relevancy(group, conditionalAccessPolicies) else ""
        #print summary
        if helper.check_cap_relevancy(group, conditionalAccessPolicies) or len(group["appRoleAssignments"]) > 0 :
            printer.print_warning(f"- {const.GREEN}[{groupType}] {displayName}{const.NC} {hasAppRoleAssignments}{capRelevant}")
        else:
            printer.print_info(f"- {const.GREEN}[{groupType}] {displayName}{const.NC} {hasAppRoleAssignments}{capRelevant}")
