import argparse, getpass

# Import config globalargs and const VERSION
from azurenum.utils.config import globalargs as globalargs # Global state
from azurenum.utils.const import VERSION



# Parse command-line arguments and store them globally via config.
def parse_args(argv = None):

    parser = argparse.ArgumentParser(
        description=f"AzurEnum - Enumerate EntraID fast! Version {VERSION}",
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=100),
        add_help=True,
    )

    # Version
    parser.add_argument('--version', action='version', version=f"AzurEnum {VERSION}")

    # Authentication Group
    auth_group = parser.add_argument_group('Authentication settings')
    auth_group.add_argument("-t", "--tenant-id", help="specify tenant to authenticate to (needed for ROPC authentication or when authenticating to a non-native tenant of the given user)", default=None)
    auth_group.add_argument("-u", "--upn", help="specify user principal name to use in ROPC or interactive authentication", default=None)
    auth_group.add_argument("-p", "--password", help="specify password to use in ROPC or interactive authentication. Leave empty for prompt", nargs='?', const="", default=None)
    auth_group.add_argument("-frt", "--foci-refresh-token", help="FOCI Refresh Token to authenticate with. Needs to be used together with --azcli-refresh-token", default=None)
    auth_group.add_argument("-art", "--azcli-refresh-token", help="AZCLI Refresh Token to authenticate with. Needs to be used together with --foci-refresh-token", default=None)
    # policy_refresh_token
    auth_group.add_argument("--mwp-refresh-token", help="[Optional] Refresh Token for [Modern Workplace Customer API Native](2e307cd5-5d2d-4499-b656-a97de9f52708). Only needed with -pol and without -naa. If omitted will try to use device code authentication", default=None)

    # idp_refresh_token
    auth_group.add_argument("--aadps-refresh-token", help="[Optional] Refresh Token for [Azure Active Directory PowerShell](1b730954-1685-4b74-9bfd-dac224a7b894). Only needed with -idp and without -naa. If omitted will try to use device code authentication", default=None)

    auth_group.add_argument("-naa", "--nested-app-auth", help="Expects Azure Portal Refresh Token for nested app authentication flow", default=None)
    auth_group.add_argument("-i", "--interactive-auth", help="Use Interactive Authentication flow with Selenium to retrieve a NAA token and use it. This is the default authentication Method", action="store_true")
    auth_group.add_argument("-ua", "--user-agent", help="specify user agent (default is MS-Edge on Windows 10)", default=None)
    auth_group.add_argument("--device-code", help="Use Device-Code Authentication flow", action="store_true")

    # Enumeration Settings Group
    enum_group = parser.add_argument_group('Enumeration settings')
    enum_group.add_argument("-rd","--recursion-depth",help="Depth for recursion when listing nested principals [Default=2]", default=2, type=int)
    enum_group.add_argument("--proxy", help="Use proxy for sending requests. Beware - will disable certificate checks! Example: http://127.0.0.1:8080", default=None)
    enum_group.add_argument("-pol","--policies",help="Query additional policies for tenant like authentication methods and device policies. Always enabled for NAA Auth. For other authentications this will need another login!", action='store_true') # Policy.ReadWrite.All
    enum_group.add_argument("-idp","--identity-provider", help="Query identity providers and federation service-configs for tenant. Always enabled for NAA Auth. For other authentications this will need another login!", action='store_true') # IdentityProvider.ReadWrite.All
    enum_group.add_argument("--show-directory-roles", help="Show results of /directoryRoles even though PIM is in use. Can help to identify role assignments outside of PIM!", action='store_true') # IdentityProvider.ReadWrite.All

    # Output Group
    output_group = parser.add_argument_group('Output')
    output_group.add_argument("-o", "--output-text", help="specify filename to save TEXT output", default=None, type=argparse.FileType('w'))
    output_group.add_argument("-j", "--output-json", help="specify filename to save JSON output", default=None, type=argparse.FileType('w'))
    output_group.add_argument("-nc", "--no-color", help="don't use colors", action='store_true')

    # Parse arguments
    _args = parser.parse_args(argv)

    if _args.password == "":
        _args.password = getpass.getpass("Password: ")
    # Pass to global args in config
    globalargs.set_args(
                        tenant_id=_args.tenant_id, 
                        upn=_args.upn, 
                        password=_args.password, 
                        foci_refresh_token=_args.foci_refresh_token, 
                        azcli_refresh_token=_args.azcli_refresh_token, 
                        aadps_refresh_token=_args.aadps_refresh_token,
                        mwp_refresh_token=_args.mwp_refresh_token,
                        nested_app_auth=_args.nested_app_auth, 
                        interactive_auth=_args.interactive_auth, 
                        user_agent=_args.user_agent, 
                        device_code=_args.device_code, 
                        recursion_depth=_args.recursion_depth, 
                        proxy=_args.proxy, 
                        policies=_args.policies, 
                        identity_provider=_args.identity_provider,
                        show_directory_roles=_args.show_directory_roles,
                        output_text=_args.output_text, 
                        output_json=_args.output_json, 
                        no_color=_args.no_color
                        )