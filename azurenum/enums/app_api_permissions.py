from azurenum.utils import const, api, printer, helper, output


def enum_app_api_permissions(servicePrincipals, tenantId, msGraphToken):
    printer.print_header("ServicePrincipal API Permissions (only listing 'Application Permissions')")
    # In principle I am only interested in SPs from an AppReg. I can fetch the AppRegs `az rest --method get --url "{const.MS_GRAPH_API}/v1.0/myorganization/applications/"` and then lookout their SPs by checking the "appId" field of the SP object
    # Once I got the SP I can ask the appRoleAssignments like this `az rest --method get --url '{const.MS_GRAPH_API}/v1.0/servicePrincipals/<servicePrincipalId>/appRoleAssignments'` which get me value[] with objects like {resourceId,resourceDisplayName,appRoleId,...}. I need to pick the resourceId and the appRoleId to ask for the API-Permissions in the next request
    # I go {const.MS_GRAPH_API}/v1.0/servicePrincipals/<resourceId> and ask for the "appRoles" which look like {id,value,displayName}. The id is the "appRoleId" from before, the value is the API-Permission and the displayname a short description

    # SP that has an AppReg in the tenant
    internalSps = [sp for sp in servicePrincipals if sp["appOwnerOrganizationId"] == tenantId]
    # SP that has not an AppReg in the tenant. Nicht interessiert in Apps, die Microsoft gehören
    externalSps = [sp for sp in servicePrincipals if sp["appOwnerOrganizationId"] not in {tenantId, const.MICROSOFT_SERVICE_TENANT_ID}]
    
    if len(internalSps) > 0:
        printer.print_info("ServicePrincipals with an AppReg in this tenant")
    # check service principals with appReg in this tenant
    for sp in internalSps:
        id = sp["id"]
        displayName = sp["displayName"]
        appRoleAssignments = api.get_msgraph_value(f"/servicePrincipals/{id}/appRoleAssignments", {}, msGraphToken)
        if appRoleAssignments != None and len(appRoleAssignments) > 0:
            jsonData = sp
            jsonAppRoleAssignments = []
            for appRoleAssignment in appRoleAssignments:
                # For each appRoleAssignment
                resourceId = appRoleAssignment["resourceId"] # where does this app has an api permission (ID)
                appRoleId = appRoleAssignment["appRoleId"] # which permission does the app has
                resourceDisplayName = appRoleAssignment["resourceDisplayName"] # where does this app has an api permission
                # jsonAppRoleAssignments.append(resourceDisplayName)
                resourceServicePrincipalAppRoles = next((sp["appRoles"] for sp in servicePrincipals if sp["id"] == resourceId), None)
                if (resourceServicePrincipalAppRoles != None):
                    appRole = next((appRole for appRole in resourceServicePrincipalAppRoles if appRole["id"] == appRoleId), None)
                    if appRole != None:
                        apiPermissionName = appRole["value"]
                        printer.print_simple(f"- {const.GREEN}[{displayName}]{const.NC} has {const.ORANGE}[{apiPermissionName}]{const.NC} in {const.CYAN}[{resourceDisplayName}]{const.NC}")
                        jsonAppRoleAssignments.append(f"{apiPermissionName} [{resourceDisplayName}]")
                    else:
                        # could not enumerate permission name, write down ID
                        printer.print_simple(f"- {const.GREEN}[{displayName}]{const.NC} has {const.ORANGE}[{appRoleId}]{const.NC} in {const.CYAN}[{resourceDisplayName}]{const.NC}")
            sp["@odata.type"] = "#microsoft.graph.servicePrincipal"
            helper.enum_nested_lists(helper.gather_nesting([sp], msGraphToken=msGraphToken), indent = "  ", jsonKey=const.PRIVILEGED_APPLICATION_OWNERS)
            print()
            jsonData["AzurEnum-ApiPermissions"] = jsonAppRoleAssignments
            output.add_json_output(const.PRIVILEGED_APPLICATIONS,jsonData)
    if len(externalSps) > 0:
        printer.print_info(f"ServicePrincipals with an AppReg in a foreign, non-Microsoft tenant")
    # check service principals with appReg in external tenant
    for sp in externalSps:
        id = sp["id"]
        displayName = sp["displayName"]
        appRoleAssignments = api.get_msgraph_value(f"/servicePrincipals/{id}/appRoleAssignments", {}, msGraphToken)
        if appRoleAssignments != None and len(appRoleAssignments) > 0:
            jsonData = sp
            jsonAppRoleAssignments = []
            for appRoleAssignment in appRoleAssignments:
                # For each appRoleAssignment
                resourceId = appRoleAssignment["resourceId"]  # where does this app has an api permission (ID)
                appRoleId = appRoleAssignment["appRoleId"]  # which permission does the app has
                resourceDisplayName = appRoleAssignment["resourceDisplayName"]  # where does this app has an api permission
                resourceServicePrincipalAppRoles = next((sp["appRoles"] for sp in servicePrincipals if sp["id"] == resourceId), None)
                if (resourceServicePrincipalAppRoles != None):
                    appRole = next((appRole for appRole in resourceServicePrincipalAppRoles if appRole["id"] == appRoleId), None)
                    if appRole != None:
                        apiPermissionName = appRole["value"]
                        printer.print_simple(f"- {const.GREEN}[{displayName}]{const.NC} has {const.ORANGE}[{apiPermissionName}]{const.NC} in {const.CYAN}[{resourceDisplayName}]{const.NC}")
                        jsonAppRoleAssignments.append(f"{apiPermissionName} [{resourceDisplayName}]")
                    else:
                        # could not enumerate permission name, write down ID
                        printer.print_simple(f"- {const.GREEN}[{displayName}]{const.NC} has {const.ORANGE}[{appRoleId}]{const.NC} in {const.CYAN}[{resourceDisplayName}]{const.NC}")
            sp["@odata.type"] = "#microsoft.graph.servicePrincipal"
            helper.enum_nested_lists(helper.gather_nesting([sp], msGraphToken=msGraphToken), indent="  ", jsonKey=const.PRIVILEGED_APPLICATION_OWNERS)
            print()
            jsonData["AzurEnum-ApiPermissions"] = jsonAppRoleAssignments
            output.add_json_output(const.PRIVILEGED_APPLICATIONS,jsonData)
