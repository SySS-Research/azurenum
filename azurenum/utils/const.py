VERSION="v1.1.5"

# Misc Constant GUIDs
AAD_PREMIUM_P2 = "eec0eb4f-6444-4f95-aba0-50c24d67f998"
AAD_PREMIUM_P1 = "41781fb2-bc02-4b7c-bd55-b576c07bb09d"
GROUP_UNIFIED_TEMPLATE_ID = "62375ab9-6b52-47ed-826b-58e47e0e304b"
GUEST_ROLE_USER = "a0b1b346-4d3e-4e8b-98f8-753987be4970" # https://learn.microsoft.com/en-us/graph/api/resources/authorizationpolicy?view=graph-rest-1.0&preserve-view=true
GUEST_ROLE_GUEST = "10dae51f-b6af-4016-8d66-8c2a99b929b3"
GUEST_ROLE_RESTRICTED = "2af84b1e-32c8-42b7-82bc-daa82404023b"
MICROSOFT_SERVICE_TENANT_ID = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"

# Authentication GUIDs and constants
AUTHORITY_URL = "https://login.microsoftonline.com/"
SCOPE_MS_GRAPH = ["https://graph.microsoft.com/.default"]
SCOPE_AAD_GRAPH = ["https://graph.windows.net/.default"]
SCOPE_ARM = ["https://management.core.windows.net/.default"]
SCOPE_MSPIM = ["01fc33a7-78ba-4d2f-a4b7-768e336e890e/.default"]
SCOPE_MAIN_IAM = ["74658136-14ec-4630-ad9b-26e160ff0fc6/.default"]  # resource id for main.iam.ad.ext.azure.com
OFFICE_CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
AZURECLI_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
MANAGED_MEETING_ROOMS_CLIENT_ID = "eb20f3e3-3dce-4d2c-b721-ebb8d4414067"

# NAA Auth
AZURE_PORTAL_CLIENT_ID = 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c'
AZURE_PORTAL_BROKER_URI = 'brk-c44b4083-3bb0-49c1-b47d-974e53cbdf3c://portal.azure.com'
ADIBIZAUX_CLIENT_ID = '74658136-14ec-4630-ad9b-26e160ff0fc6'
ELMADMIN_CLIENT_ID = '0032593d-6a05-4847-8ca4-4b6220ed2a1e'
# FOCI clients see https://github.com/dirkjanm/family-of-client-ids-research/blob/main/known-foci-clients.csv

# Non-FOCI Clients:
# If user authentication policies are supposed to be queried we need another client id for scope: Policy.ReadWrite.All
MODERN_WORKPLACE_CUSTOMER_API_NATIVE_CLIENT_ID = "2e307cd5-5d2d-4499-b656-a97de9f52708" #-> not possible to get IdentitiyProviders with this
AAD_POWERSHELL_CLIENT_ID = "1b730954-1685-4b74-9bfd-dac224a7b894" # IdentityProvider.ReadWrite -> not possible to get Policies with this
# keep second login and implement BroCI meanwhile instead...

# Could use an enum class for this? maybe refactor in the future
DEVICE_CODE_FLOW="DEVICE_CODE_FLOW"
ROPC_FLOW="ROPC_FLOW"
REFRESH_TOKEN_FLOW="REFRESH_TOKEN_FLOW"

# Default User-Agent Edge on Windows 10
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.2277.112"

# Constant API URLs
AAD_GRAPH_API = "https://graph.windows.net"
MS_GRAPH_API = "https://graph.microsoft.com"
AZURE_PORTAL = "https://portal.azure.com"
ARM_API = "https://management.azure.com"
MAIN_IAM_API = "https://main.iam.ad.ext.azure.com"

# Constanst JSON Keys
BASIC_INFO = "basicInfo"
DEVICE_SETTINGS = "deviceSettings"
GUEST_INFO = "guestInfo"
USER_SETTINGS = "userSettings"
DIRECTORY_ROLES = "directoryRoles"
PIM_ASSIGNMENTS = "pimAssignments"
PRIVILEGED_APPLICATIONS = "privilegedApplications"
PRIVILEGED_APPLICATION_OWNERS = "privilegedApplicationOwners"
NO_MFA = "noMfa"
SYNCED = "synced"
LEGACY_FINDINGS = "legacy-findings"


# Set colors
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[0;33m"
CYAN = "\033[0;36m"
ORANGE = "\033[38;5;208m"
NC = "\033[0m"  # No Color



