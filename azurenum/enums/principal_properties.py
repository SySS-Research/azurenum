from azurenum.utils import const, printer

#search for keywords in principal properties
def search_principal_properties(groups, servicePrincipals, usersBeta):
    printer.print_header("Juicy Info in User, Group and Apps Properties")
    printer.print_info("Searching for juicy info in principal properties ...")
    keywords = ["passwo", "cred", "access", "zugang", "login", "anmeld", "initial","kennw","secret"]
    
    if usersBeta == None:
        printer.print_error("Could not fetch users")
    else:    
        for user in usersBeta:
            for key in user:
                if (isinstance(user[key], str) and key != "passwordPolicies"): # Exclude "passwordPolicies" string which leads to false positives
                    if any(keyword in user[key].lower() for keyword in keywords):
                        upn = user["userPrincipalName"]
                        printer.print_info(f"[USER] {upn} => {const.RED}({key}): {user[key]}{const.NC}")
    if groups != None:
        for group in [group for group in groups if group["description"] != None]:
            if any(keyword in group["description"].lower() for keyword in keywords):
                displayName = group["displayName"]
                desc = group["description"]
                printer.print_info(f"[GROUP] {displayName} => {const.RED}(description): {desc}{const.NC}")
    if servicePrincipals != None:
        for spn in servicePrincipals:
            if spn["notes"] != None:
                if any(keyword in spn["notes"].lower() for keyword in keywords):
                    displayName = spn["displayName"]
                    notes = spn["notes"]
                    printer.print_info(f"[APP] {displayName} => {const.RED}(notes): {notes}{const.NC}")

