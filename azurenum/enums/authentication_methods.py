from azurenum.utils import const, printer

# enum authentication methods users can use
def enum_authentication_methods(authMethods=None, domain=None):
    printer.print_header(f"Authentication methods for tenant {domain}")
    printer.print_link("Portal: https://portal.azure.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods")
    if authMethods == None:
        printer.print_error("Could not fetch authentication methods")
    else:
        for methods in authMethods["authenticationMethodConfigurations"]:
            method_id = methods["id"]
            method_status = methods["state"]
            color = const.YELLOW
            if method_status == "enabled":
                color = const.GREEN
            printer.print_info(f"- {const.NC}[{method_id}]{const.NC} {color}{method_status}{const.NC}")
            if method_id ==  "MicrosoftAuthenticator":
                if methods["isSoftwareOathEnabled"] == True:
                    printer.print_warning(f"     Authenticator OTP: {const.RED}enabled{const.NC}") 

