import platform, json, jwt, sys, re
from azurenum.utils import const, printer, output, api
from azurenum.utils.config import globalargs as globalargs
from azurenum.utils.config import globalconfig as globalconfig


# helper method to remove circular references before dumpin json to file
def remove_circular_refs(obj, seen=None):
    if seen is None:
        seen = set()
    if id(obj) in seen:
        # circular reference, remove it.
        return None
    seen.add(id(obj))
    res = obj
    if isinstance(obj, dict):
        res = {
            remove_circular_refs(k, seen): remove_circular_refs(v, seen)
            for k, v in obj.items()}
    elif isinstance(obj, (list, tuple, set, frozenset)):
        res = type(obj)(remove_circular_refs(v, seen) for v in obj)
    # remove id again; only *nested* references count
    seen.remove(id(obj))
    return res



if platform.system() == 'Windows':
    IS_WINDOWS = True
else:
    IS_WINDOWS = False



def get_boolean(value): # return bool True or False depending on input. MS graph is inconsistent with bools - we need to sanitize that somehow
    true_array = [True,"true", "True"]
    false_array = [False, "false", "False"]
    if value in true_array:
        return True
    elif value in false_array:
        return False
    else:
        printer.print_error(f"Could not convert value: {value} to bool value!")

def gather_nesting(list, depth=0, msGraphToken="", groupPim=True, seen=None):
    if seen is None:
        seen = set()

    if depth > globalargs.recursion_depth or globalargs.recursion_depth == 0:
        return list
    if list == None or len(list) == 0:
        return list
    else:
        for object in list:
            objectId = object["id"]
            type = object["@odata.type"]
            # cyclic / duplicate reference -> mark and stop expanding, but keep keys consistent
            if objectId in seen:
                object["AzurEnum-AlreadyExpanded"] = True
                if type == "#microsoft.graph.group":
                    object["members"] = []
                    object["owners"] = []
                    object["eligibleOwners"] = []
                    object["eligibleMembers"] = []
                elif type == "#microsoft.graph.servicePrincipal":
                    object["spOwners"] = []
                    object["appRegOwners"] = []
                continue

            seen.add(objectId)

            if type == "#microsoft.graph.group":
                group = get_directoryObjects_byIds([objectId],msGraphToken)[0]
                if group == None:
                    return
                members = []
                owners = []
                memberResult = api.get_msgraph(f"/groups/{objectId}",{"$expand":"members"},msGraphToken)
                if memberResult != None:
                    members = memberResult.get("members",[])
                ownerResult = api.get_msgraph(f"/groups/{objectId}",{"$expand":"owners"},msGraphToken)
                if ownerResult != None:
                    owners = ownerResult.get("owners",[])
                eligibleOwners = []
                eligibleMembers = []
                if groupPim and (group.get("membershipRule") == None):
                    eligibles = api.get_msgraph_value(f"/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances", {"$expand":"principal", "$filter":f"groupId eq '{objectId}'"}, globalargs.aadps_access_token)
                    if eligibles != None:
                        for eligible in eligibles:
                            resolved_principals = get_directoryObjects_byIds([eligible.get("principal",{}).get("id")], msGraphToken)
                            if eligible.get("accessId") == "owner":
                                eligibleOwners.append(resolved_principals[0])
                            elif eligible.get("accessId") == "member":
                                eligibleMembers.append(resolved_principals[0])
                            else:
                                printer.print_error(f"PIM group accessID is neither member nor owner: {eligible.get("accessId")}")
                object["members"] = gather_nesting(members, depth+1, msGraphToken, groupPim, seen)
                object["owners"] = gather_nesting(owners, depth+1, msGraphToken, groupPim, seen)
                object["eligibleOwners"] = gather_nesting(eligibleOwners, depth+1, msGraphToken, groupPim, seen)
                object["eligibleMembers"] = gather_nesting(eligibleMembers, depth+1, msGraphToken, groupPim, seen)
            elif type == "#microsoft.graph.servicePrincipal":
                spOwners, appRegOwners = enum_application_owners(object)
                object["spOwners"] = gather_nesting(spOwners, depth+1, msGraphToken, groupPim, seen)
                object["appRegOwners"] = gather_nesting(appRegOwners, depth+1, msGraphToken, groupPim, seen)
    return list

#helper method that prints nested listes (see gather_nesting) and adds interesting principals to log and json output
# is called recursively until --recursion-depth is reached
def enum_nested_lists(objects, indent="  ", level = 0, jsonKey="", permission="nestedPermission"):
    connector_last = "└──"
    connector_mid = "├──"
    connector_skip = "│"
    if globalargs.recursion_depth == 0:
        return
    for index, obj in enumerate(objects):
        is_obj_last = (index == len(objects) - 1)
        connector = connector_last if is_obj_last else connector_mid
        objId = ""
        displayName = ""
        synced = ""
        type = ""
        friendlyType = ""
        lacksMfa = ""
        roleAssignable = ""
        dynamic = ""
        public = ""
        seen = ""
        try:
            objId = obj["id"]
            displayName = obj.get("displayName",objId)
            type = obj["@odata.type"]
            if type == "#microsoft.graph.user":
                objId = obj["userPrincipalName"] # for users, show UPN instead of ID
                active = "" if obj["accountEnabled"] else " (DISABLED)"
                friendlyType = f"USER{const.YELLOW}{active}{const.NC}"
                if obj["onPremisesSyncEnabled"]:
                    synced = f" {const.ORANGE}(synced!){const.NC}"
                    if level > 0:
                        obj["AzurEnum-EntraRole"] = permission
                        output.add_json_output(f"{jsonKey}-{const.SYNCED}", obj)
                else:
                    synced = ""
                userHasMfa = hasUserMFA(objId)
                if userHasMfa:
                    lacksMfa = ""
                elif userHasMfa == None:
                    lacksMfa = " (MFA unknown)"
                else:
                    lacksMfa = f" {const.ORANGE}(No MFA Methods!){const.NC}"
                    if level > 0:
                        obj["AzurEnum-EntraRole"] = permission
                        output.add_json_output(f"{jsonKey}-{const.NO_MFA}", obj)
            elif type == "#microsoft.graph.group":
                friendlyType = "GROUP"# if assignment["principal"]["membershipRule"] is None else f"GROUP {const.YELLOW}(Dynamic!){const.NC}" # -- Should never appear!
                if obj["onPremisesSyncEnabled"]:
                    synced = f" {const.ORANGE}(synced!){const.NC}"
                    if level > 0:
                        obj["AzurEnum-EntraRole"] = permission
                        output.add_json_output(f"{jsonKey}-{const.SYNCED}", obj)
                else:
                    synced = ""
                if not obj["isAssignableToRole"]:
                    roleAssignable = f" {const.ORANGE}(not role assignable!){const.NC}"
                    if level > 0:
                        obj["AzurEnum-EntraRole"] = permission
                        output.add_json_output(f"{jsonKey}-{const.NO_PRIVILEGED_MANAGEMENT}", obj)
                if obj["membershipRule"] != None:
                    dynamic = f" {const.ORANGE}(dynamic!){const.NC}"
                    if level > 0:
                        obj["AzurEnum-EntraRole"] = permission
                        output.add_json_output(f"{jsonKey}-{const.DYNAMIC}", obj)
                elif obj["visibility"] == "Public":
                    public = f" {const.RED}(public!){const.NC}"
                    if level > 0:
                        obj["AzurEnum-EntraRole"] = permission
                        output.add_json_output(f"{jsonKey}-{const.PUBLIC}", obj)

                if obj.get("AzurEnum-AlreadyExpanded", False) == True:
                    seen = f" {const.CYAN}(already expanded!){const.NC}"
            elif type == "#microsoft.graph.servicePrincipal":
                friendlyType = "SERVICE_PRINCIPAL"
                if level > 0:
                    obj["AzurEnum-EntraRole"] = permission
                    output.add_json_output(const.PRIVILEGED_APPLICATIONS,obj)
            elif type == 'UNRESOLVED':
                friendlyType = "UNRESOLVED"
            else:
                friendlyType = "UNKNOWN_TYPE"
        except Exception as e:
            printer.print_error(f"Error {e} on printing principal: {obj}")
        if level != 0:
            printer.print_simple(f"{indent}{connector}[{friendlyType}] {objId} ({displayName}) {synced}{lacksMfa}{roleAssignable}{dynamic}{public}{seen}")
        # Prepare indent for children
        child_indent = indent + ("      " if is_obj_last else f"{connector_skip}     ")

        # check if next level is allowed to be printed
        if level <= globalargs.recursion_depth - 1:
            # only works for groups
            if type == "#microsoft.graph.group":
                # Print owners
                owners = obj["owners"]
                if owners:
                    label_connector = connector_last if not (obj["members"] or obj["eligibleOwners"] or obj["eligibleMembers"]) else connector_mid
                    printer.print_simple(f"{child_indent}{label_connector}{const.YELLOW}Owners{const.NC}")
                    enum_nested_lists(owners, child_indent + (f"{connector_skip}     " if (obj["members"] or obj["eligibleOwners"] or obj["eligibleMembers"]) else "      "), level=level+1, jsonKey=jsonKey, permission=f"{permission}-groupOwner")

                # print members
                members = obj["members"]
                if members:
                    label_connector = connector_last if not (obj["eligibleOwners"] or obj["eligibleMembers"]) else connector_mid
                    printer.print_simple(f"{child_indent}{label_connector}{const.YELLOW}Members{const.NC}")
                    enum_nested_lists(members, child_indent + (f"{connector_skip}     " if (obj["eligibleOwners"] or obj["eligibleMembers"]) else "      "), level=level+1, jsonKey=jsonKey, permission=permission)

                # print eligible owners
                eligibleOwners = obj["eligibleOwners"]
                if eligibleOwners:
                    label_connector = connector_last if not obj["eligibleMembers"] else connector_mid
                    printer.print_simple(f"{child_indent}{label_connector}{const.YELLOW}Owners {const.CYAN}[Eligible]{const.NC}")
                    enum_nested_lists(eligibleOwners, child_indent + (f"{connector_skip}     " if obj["eligibleMembers"] else "      "), level=level+1, jsonKey=jsonKey, permission=f"{permission}-eligibleGroupOwner")

                # print eligible members
                eligibleMembers = obj["eligibleMembers"]
                if eligibleMembers:
                    printer.print_simple(f"{child_indent}{connector_last}{const.YELLOW}Members {const.CYAN}[Eligible]{const.NC}")
                    enum_nested_lists(eligibleMembers, child_indent + "      " , level=level+1, jsonKey=jsonKey, permission=permission)

            # if object is SP
            elif type == "#microsoft.graph.servicePrincipal":
                spOwners = obj["spOwners"]
                if spOwners:
                    owners_label_connector = connector_last if not obj["appRegOwners"] else connector_mid
                    printer.print_simple(f"{child_indent}{owners_label_connector}{const.YELLOW}Owners{const.NC}")
                    enum_nested_lists(spOwners, child_indent + ("      "  if not obj["appRegOwners"] else f"{connector_skip}     "), level=level+1, jsonKey=jsonKey, permission=f"{permission}-spOwner")
                appRegOwners = obj["appRegOwners"]
                if appRegOwners:
                    printer.print_simple(f"{child_indent}{connector_last}{const.YELLOW}AppReg-Owners{const.NC}")
                    enum_nested_lists(appRegOwners, child_indent + "      " , level=level+1, jsonKey=jsonKey, permission=f"{permission}-appRegOwner")



# helper method that returns decoded JWT
def decode_jwt(token):
    try:
        decoded_token = jwt.decode(token, options={"verify_signature": False})  # No signature verification
        return decoded_token
    except Exception as e:
        print(f"Error decoding JWT: {e}")
        sys.exit(1)


# helper method to check MFA state of upn against global registration details
def hasUserMFA(userPrincipalName):
    if globalconfig.userRegistrationDetails == None:
        # Information on MFA could not be fetched
        return None # unknown whether MFA methods are set

    # pick user mfa methods
    registrationDetail = next((registrationDetail for registrationDetail in globalconfig.userRegistrationDetails if registrationDetail["userPrincipalName"] == userPrincipalName), None)

    if registrationDetail == None:
        printer.print_error(f"Registration Details not found for: {userPrincipalName}")
        return None

    return registrationDetail["isMfaCapable"]


# helper method that uses global list of appRegs and SPs to search for sp and appReg owners
def enum_application_owners(servicePrincipal):
    appRegs = globalconfig.appRegs
    servicePrincipals = globalconfig.servicePrincipals
    spOwners = []
    appRegOwners = []
    if servicePrincipals == None:
        return spOwners,appRegOwners
    spOwners = next((sp["owners"] for sp in servicePrincipals if sp["id"] == servicePrincipal["id"]), None)
    if spOwners == None:
        printer.print_error("Principal not found in ServicePrincipals")
    #check if sp is internal or external
    try:
        if servicePrincipal["appOwnerOrganizationId"] == globalconfig.tenantId:
            appRegOwners = next((appReg["owners"] for appReg in appRegs if appReg["appId"] == servicePrincipal["appId"]), None)
    except Exception as e:
        appRegOwners = []
    return spOwners, appRegOwners


# helper method which simply greps CAP output for principal id
def check_cap_relevancy(principal, conditionalAccessPolicies):
    if conditionalAccessPolicies == None:
        return False
    for policy in conditionalAccessPolicies:
        # stupidly grep for pincipalId in policies and return true if it is mentioned
        result = re.findall(principal["id"], json.dumps(policy))
        if len(result) > 0:
            return True
    return False



# resolve id to get full object
def get_directoryObjects_byIds(ids, msGraphToken):
    data = {"ids": ids}
    result = api.post_msgraph("/directoryObjects/getByIds", {}, msGraphToken, data, version="beta")
    resolved_ids = result.get("value",[])
    if len(resolved_ids) > 0: 
        return resolved_ids
    else:
        printer.print_error(f"Could not resolve the following ids: {ids}")
        unresolved_objects = []
        for id in ids:
            unresolved_objects.append({"@odata.type": "UNRESOLVED", "id": f"{id}"})
        return unresolved_objects


#helper method to resolve tenant id to tenant infos
def get_tenant_info_by_id(tenant_id, token):
    tenant_info = api.get_msgraph(f"/tenantRelationships/findTenantInformationByTenantId(tenantId='{tenant_id}')", {}, token, version="beta")
    if tenant_info != None:
        return tenant_info # -> in der enum funktion dann vmtl if tenant_info !=None: print(f"Tenant {tenant_info["displayname"]} ({tenant_info["defaultDomainName"]}) uses default trust settings")  oder sowas :) kannst dir das objekt ja mal anschauen
    else:
        return None

