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


# helper method that checks objectlist for Owners/Members (if group) or owners/AppRegOwner (if servicePrincipal)
# is called recursively until --recursion-depth is reached
def gather_nesting(list, depth=0, msGraphToken=""):
    if depth > globalargs.recursion_depth or globalargs.recursion_depth == 0:
        return list
    if list == None or len(list) == 0:
        return list
    else:
        for object in list:
            objectId = object["id"]
            type = object["@odata.type"]
            if type == "#microsoft.graph.group":
                members = api.get_msgraph(f"/groups/{objectId}",{"$expand":"members"},msGraphToken)["members"]
                owners = api.get_msgraph(f"/groups/{objectId}",{"$expand":"owners"},msGraphToken)["owners"]
                object["members"]=gather_nesting(members,depth+1,msGraphToken)
                object["owners"]=gather_nesting(owners,depth+1,msGraphToken)
            elif type == "#microsoft.graph.servicePrincipal":
                spOwners, appRegOwners = enum_application_owners(object)
                object["spOwners"]=gather_nesting(spOwners,depth+1,msGraphToken)
                object["appRegOwners"]=gather_nesting(appRegOwners,depth+1,msGraphToken)
    return list


def get_boolean(value): # return bool True or False depending on input. MS graph is inconsistent with bools - we need to sanitize that somehow
    true_array = [True,"true", "True"]
    false_array = [False, "false", "False"]
    if value in true_array:
        return True
    elif value in false_array:
        return False
    else:
        printer.print_error(f"Could not convert value: {value} to bool value!")



#helper method that prints nested listes (see gather_nesting) and adds interesting principals to log and json output
# is called recursively until --recursion-depth is reached
def enum_nested_lists(objects, indent="  ", level = 0, jsonKey=""):
    #print(f"Trying to print: {objects}")
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
        #print(f"set entra role to nestedPermission for object {obj}")
        try:
            objId = obj["id"]
            displayName = obj["displayName"]
            type = obj["@odata.type"]
            if type == "#microsoft.graph.user":
                objId = obj["userPrincipalName"] # for users, show UPN instead of ID
                active = "" if obj["accountEnabled"] else " (DISABLED)"
                friendlyType = f"USER{const.YELLOW}{active}{const.NC}"
                # friendlyType = "USER"
                if obj["onPremisesSyncEnabled"]:
                    synced = f" {const.ORANGE}(synced!){const.NC}"
                    if level > 0:
                        obj["AzurEnum-EntraRole"] = "nestedPermission"
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
                        obj["AzurEnum-EntraRole"] = "nestedPermission"
                        output.add_json_output(f"{jsonKey}-{const.NO_MFA}", obj)
            elif type == "#microsoft.graph.group":
                friendlyType = "GROUP"# if assignment["principal"]["membershipRule"] is None else f"GROUP {const.YELLOW}(Dynamic!){const.NC}" # -- Should never appear!
                if obj["onPremisesSyncEnabled"]:
                    synced = f" {const.ORANGE}(synced!){const.NC}"
                    if level > 0:
                        obj["AzurEnum-EntraRole"] = "nestedPermission"
                        output.add_json_output(f"{jsonKey}-{const.SYNCED}", obj)
                else:
                    synced = ""
            elif type == "#microsoft.graph.servicePrincipal":
                friendlyType = "SERVICE_PRINCIPAL"
                if level > 0:
                    obj["AzurEnum-EntraRole"] = "nestedPermission"
                    #   obj["AzurEnum-ApiPermissions"] = "nestedPermission"
                    output.add_json_output(const.PRIVILEGED_APPLICATIONS,obj)
            else:
                friendlyType = "UNKNOWN_TYPE"
        except Exception as e:
            printer.print_error(f"Error {e} on printing principal: {obj}")
        if level != 0:
            printer.print_simple(f"{indent}{connector}[{friendlyType}] {objId} ({displayName}) {synced}{lacksMfa}")
        # Prepare indent for children
        child_indent = indent + ("      " if is_obj_last else f"{connector_skip}     ")

        # check if next level is allowed to be printed
        if level <= globalargs.recursion_depth - 1:
            # only works for groups
            if type == "#microsoft.graph.group":
                # Print owners
                owners = obj["owners"]
                if owners:
                    owners_label_connector = connector_last if not obj["members"] else connector_mid
                    printer.print_simple(f"{child_indent}{owners_label_connector}{const.YELLOW}Owners{const.NC}")
                    enum_nested_lists(owners, child_indent + ("      " if not obj["members"] else f"{connector_skip}     "), level=level+1, jsonKey=jsonKey)

                # print members
                members = obj["members"]
                if members:
                    printer.print_simple(f"{child_indent}{connector_last}{const.YELLOW}Members{const.NC}")
                    enum_nested_lists(members, child_indent + "      " , level=level+1, jsonKey=jsonKey)
            # if object is SP
            elif type == "#microsoft.graph.servicePrincipal":
                spOwners = obj["spOwners"]
                if spOwners:
                    owners_label_connector = connector_last if not obj["appRegOwners"] else connector_mid
                    printer.print_simple(f"{child_indent}{owners_label_connector}{const.YELLOW}Owners{const.NC}")
                    enum_nested_lists(spOwners, child_indent + ("      "  if not obj["appRegOwners"] else f"{connector_skip}     "), level=level+1, jsonKey=jsonKey)
                appRegOwners = obj["appRegOwners"]
                if appRegOwners:
                    printer.print_simple(f"{child_indent}{connector_last}{const.YELLOW}AppReg-Owners{const.NC}")
                    enum_nested_lists(appRegOwners, child_indent + "      " , level=level+1, jsonKey=jsonKey)



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
    if result != None:
        return result["value"]
    else:
        printer.print_error(f"Could not resolve the following ids: {ids}")
        return []


#helper method to resolve tenant id to tenant infos
def get_tenant_info_by_id(tenant_id, token):
    tenant_info = api.get_msgraph(f"/tenantRelationships/findTenantInformationByTenantId(tenantId='{tenant_id}')", {}, token, version="beta")
    if tenant_info != None:
        return tenant_info # -> in der enum funktion dann vmtl if tenant_info !=None: print(f"Tenant {tenant_info["displayname"]} ({tenant_info["defaultDomainName"]}) uses default trust settings")  oder sowas :) kannst dir das objekt ja mal anschauen
    else:
        return None

