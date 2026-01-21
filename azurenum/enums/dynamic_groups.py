from azurenum.utils import const, printer, helper

# check dynamic groups for approle assignments and cap relevancy
def enum_dynamic_groups(groups, conditionalAccessPolicies=None):
    if groups == None:
        return # Couldnt fetch groups before

    dynamicGroups = [group for group in groups if "DynamicMembership" in group["groupTypes"]]
    printer.print_header("Dynamic groups")
    printer.print_link("Exploitation: https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/dynamic-groups.html")
    printer.print_info(f"{len(dynamicGroups)} Dynamic Groups found")
    if len(dynamicGroups) == 0:
        return
    for group in dynamicGroups:
        displayName = group["displayName"]
        membershipRule = group["membershipRule"]
        groupType = "Security"
        if "Unified" in group["groupTypes"]:
            groupType = "m365"
        #check if group as approle assignments
        hasAppRoleAssignments = f"{const.YELLOW} (Has AppRoleAssignments){const.NC}" if len(group["appRoleAssignments"]) > 0 else ""
        # check if group is mentioned in CAPs 
        capRelevant = f"{const.YELLOW} (CAP Relevant!){const.NC}" if helper.check_cap_relevancy(group, conditionalAccessPolicies) else ""

        #print summary
        if helper.check_cap_relevancy(group, conditionalAccessPolicies) or len(group["appRoleAssignments"]) > 0 :
            printer.print_warning(f"- {const.GREEN}[{groupType}] {displayName}{const.NC}: {membershipRule} {hasAppRoleAssignments}{capRelevant}")
        else:
            printer.print_info(f"- {const.GREEN}[{groupType}] {displayName}{const.NC}: {membershipRule} {hasAppRoleAssignments}{capRelevant}")
