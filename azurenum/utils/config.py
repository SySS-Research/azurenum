from dataclasses import dataclass

@dataclass
class AppConfig:
# define some globals
    servicePrincipals = None
    appRegs = None
    tenantId = None
    userRegistrationDetails = None
    log_content = ""
    json_content = {}


# Container for all CLI arguments.
@dataclass
class Args:
    tenant_id = None
    upn = None
    password = None
    refresh_token = None
    nested_app_auth = None
    interactive_auth = False
    user_agent = None
    device_code = False
    recursion_depth: int = 1
    proxy = None
    policies = False
    identity_provider = False
    output_text = None  # File path (not file object)
    output_json = None  # File path (not file object)
    no_color = False

    def __init__(self, tenant_id=None, upn=None, password=None, refresh_token=None, nested_app_auth=None, interactive_auth=False, user_agent=None, device_code=False, recursion_depth=2, proxy=None, policies=False, identity_provider=False, show_directory_roles=False, output_text=None, output_json=None, no_color=False):
        self.tenant_id = tenant_id
        self.upn = upn
        self.password = password
        self.refresh_token = refresh_token
        self.nested_app_auth = nested_app_auth
        self.interactive_auth = interactive_auth
        self.user_agent = user_agent
        self.device_code = device_code
        self.recursion_depth = recursion_depth
        self.proxy = proxy
        self.policies = policies
        self.identity_provider = identity_provider
        self.show_directory_roles = show_directory_roles
        self.output_text = output_text
        self.output_json = output_json
        self.no_color = no_color

    def set_args(self, tenant_id=None, upn=None, password=None, refresh_token=None, nested_app_auth=None, interactive_auth=False, user_agent=None, device_code=False, recursion_depth=2, proxy=None, policies=False, identity_provider=False, show_directory_roles=False, output_text=None, output_json=None, no_color=False):
        self.tenant_id = tenant_id
        self.upn = upn
        self.password = password
        self.refresh_token = refresh_token
        self.nested_app_auth = nested_app_auth
        self.interactive_auth = interactive_auth
        self.user_agent = user_agent
        self.device_code = device_code
        self.recursion_depth = recursion_depth
        self.proxy = proxy
        self.policies = policies
        self.identity_provider = identity_provider
        self.show_directory_roles = show_directory_roles
        self.output_text = output_text
        self.output_json = output_json
        self.no_color = no_color
        

    def get_args(self):
        return self




# global instances of data classes
globalconfig = AppConfig()
globalargs = Args()


