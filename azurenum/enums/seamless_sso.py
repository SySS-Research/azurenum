from azurenum.utils import const, printer
from datetime import datetime

def enum_seamless_sso(sso_info=None):
    #expects data from get_main_iam("/Directories/GetSeamlessSingleSignOnDomains",{},mainIamAccessToken)
    printer.print_header("Seamless-SSO Info")
    printer.print_link(f"Portal: {const.AZURE_PORTAL}/?feature.msaljs=false#view/Microsoft_AAD_IAM/SeamlessSingleSignOnDetailsBlade")

    if sso_info == None:
        printer.print_error("Could not fetch Seamless-SSO settings")
        return
    elif len(sso_info) == 0:
        printer.print_info("No Domains with Seamless-SSO enabled were found!")
    else:
        printer.print_info(f"Found {len(sso_info)} domain(s) with Seamless SSO enabled...")
        #[{"domainName":"example.org","keyCreationDateTime":"1970-01-01T01:01:11.0101Z","status":1}]
        #status 0 -> ??
        #status 1 -> "We recommend that you roll over Kerberos decryption key(s) for one or more of your on-premises domains. Click here to learn more."
        #status 2 -> ??
        # status 3 -> ??
        print()
        now = datetime.utcnow()

        for domain in sso_info:
            key_creation_time = domain.get("keyCreationDateTime")
            kc_timestamp = datetime.fromisoformat(key_creation_time[:-1])
            difference_days = (now - kc_timestamp).days
            name = domain.get("domainName")
            if difference_days > 50 * 365:  # More than 50 years
                printer.print_warning(f"{name}: Last key rotation on: {const.RED}{key_creation_time}{const.NC}")
            elif difference_days > 365:  # More than a year
                printer.print_warning(f"{name}: Last key rotation on: {const.ORANGE}{key_creation_time}{const.NC}")
            elif difference_days > 30:  # More than 30 days
                printer.print_warning(f"{name}: Last key rotation on: {const.YELLOW}{key_creation_time}{const.NC}")
            else:
                printer.print_info(f"{name}: Last key rotation on: {const.GREEN}{key_creation_time}{const.NC}")

