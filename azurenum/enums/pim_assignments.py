from azurenum.utils import const, printer, helper, output
import copy

# enum all pim assignments. depending on --recursion-depth will also query nested groups/owners/appregOwners
def enum_pim_assignments(users, pimAssignments, msGraphToken, assignments_outside_pim=0):
    printer.print_header("PIM Assignments")

    if pimAssignments == None:
        # PIM assignments could not be fetched, return
        return

    if assignments_outside_pim > 0:
        printer.print_warning(f"There seem to be {assignments_outside_pim} role assignments outside of PIM!")
        printer.print_warning("Use --show-directory-roles to additionally show 'Administrative Roles' section")
        print()

    roles = set([result["roleDefinition"]["displayName"] for result in pimAssignments])
    for role in roles:
        assignments = [result for result in pimAssignments if result["roleDefinition"]["displayName"] == role]
        count = len(assignments)
        printer.print_info(f"{role}: {count}")
        # If assignment expired, its not shown
        for assignment in assignments:
            principalId = assignment["principal"]["id"]
            displayName = assignment["principal"]["displayName"]
            type = assignment["principal"]["@odata.type"]

            # Parameters will be set for user objects
            lacksMfa = ""
            synced = ""
            #nestedlists = helper.gather_nesting([assignment["principal"]])
            enrichedList = None
            if type == "#microsoft.graph.user":
                principalId = assignment["principal"]["userPrincipalName"] # for users, show UPN instead of ID 
                               
                # Check whether synced & no MFA methods
                userObject = next((user for user in users if user["userPrincipalName"] == principalId), None)
                if userObject == None:  # edge case if the assigned user was deleted
                    continue
                # check mfa
                userHasMfa = helper.hasUserMFA(principalId)
                
                # include account state on type
                active = "" if userObject.get("accountEnabled") else " (DISABLED)"
                friendlyType = f"USER{const.YELLOW}{active}{const.NC}"

                #prepare for output
                enrichedPrincipal = copy.deepcopy(userObject)
                enrichedPrincipal["AzurEnum-EntraRole"] = assignment
                if userHasMfa:
                    lacksMfa = "" 
                elif userHasMfa == None:
                    lacksMfa = " (MFA unknown)"
                else: 
                    lacksMfa = f" {const.ORANGE}(No MFA Methods!){const.NC}"
                    output.add_json_output(f"{const.PIM_ASSIGNMENTS}-{const.NO_MFA}", enrichedPrincipal)
                # check synced
                if userObject == None:
                    synced = f" {const.RED}(user not found!){const.NC}"
                else:
                    synced = f" {const.ORANGE}(synced!){const.NC}" if userObject["onPremisesSyncEnabled"] else ""
                    if userObject["onPremisesSyncEnabled"]:
                        output.add_json_output(f"{const.PIM_ASSIGNMENTS}-{const.SYNCED}", enrichedPrincipal)
            elif type == "#microsoft.graph.group":
                friendlyType = "GROUP" if assignment["principal"]["membershipRule"] is None else f"GROUP {const.YELLOW}(Dynamic!){const.NC}" # -- Should never appear!
                #check synced
                synced = f" {const.ORANGE}(synced!){const.NC}" if assignment["principal"]["onPremisesSyncEnabled"] else ""
                if assignment["principal"]["onPremisesSyncEnabled"]:
                    enrichedPrincipal = copy.deepcopy(assignment["principal"])
                    enrichedPrincipal["AzurEnum-EntraRole"] = assignment
                    output.add_json_output(f"{const.PIM_ASSIGNMENTS}-{const.SYNCED}", assignment["principal"])
                enrichedList = helper.gather_nesting([assignment["principal"]], msGraphToken=msGraphToken)
            elif type == "#microsoft.graph.servicePrincipal":
                friendlyType = "SERVICE_PRINCIPAL"
                enrichedList = helper.gather_nesting([assignment["principal"]], msGraphToken=msGraphToken)
                jsonData = assignment["principal"]
                jsonData["AzurEnum-EntraRole"] = assignment              
                output.add_json_output(const.PRIVILEGED_APPLICATIONS,jsonData)
            else:
                friendlyType = "UNKNOWN_TYPE"
            
            directoryScope = f"{const.YELLOW}{{{assignment['directoryScopeId']}}}{const.NC}" if assignment["directoryScopeId"] != "/" else ""
            isPermanent = f"{const.RED}[Permanent]{const.NC}" if assignment["scheduleInfo"]["expiration"]["type"] == "noExpiration" else ""
            assignmentState = "Active" if "assignmentType" in assignment else "Eligible"
            stateText = f"{const.GREEN}[{assignmentState}]{const.NC}" if assignmentState == "Active" else f"{const.CYAN}[{assignmentState}]{const.NC}"
            printer.print_simple(f"- [{friendlyType}] {directoryScope} {principalId} ({displayName}) {isPermanent}{stateText}{synced}{lacksMfa}")
            if type == "#microsoft.graph.group" or  type == "#microsoft.graph.servicePrincipal":
                helper.enum_nested_lists(enrichedList, jsonKey=const.PIM_ASSIGNMENTS)
