from azurenum.utils import printer

# enumerate Federation and IDP settings
def enum_idps(identityProviders, federation_config):
    printer.print_header("IDP and Federation Settings")
    printer.print_link("Portal: https://portal.azure.com/#view/Microsoft_AAD_IAM/CompanyRelationshipsMenuBlade/~/IdentityProviders")
    # lists e.g. SAML IDPs
    if federation_config != None and len(federation_config) != 0:
        printer.print_info("Listing Federation Configs")
        for config in federation_config:
            displayName = config["displayName"]
            issuerUri = config["issuerUri"]
            preferredAuthenticationProtocol = config["preferredAuthenticationProtocol"]
            printer.print_warning(f" - [{preferredAuthenticationProtocol}] \"{displayName}\" ({issuerUri})")
        print()
    else:
        printer.print_info("No Federation-Services configured")
    # lists further idps and gives warning if it is not microsoft built-in idp
    if identityProviders != None and len(identityProviders) > 0:
        printer.print_info("Listing Identity Providers")
        for idp in identityProviders:
            if idp["@odata.type"] == "#microsoft.graph.builtInIdentityProvider":
                printer.print_info(f" - {idp["displayName"]}")
            else:
                printer.print_warning(f" - {idp["displayName"]} ({idp["id"]}) - Type: {idp["identityProviderType"]}")
    else:
        printer.print_info("No Identity Providers configured")
