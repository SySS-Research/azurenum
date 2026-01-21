#selenioum for interactieauth
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.common.exceptions import WebDriverException
import msal, json, time, sys
#needed utils
from azurenum.utils import const, sessions, printer
from azurenum.utils.config import globalargs as globalargs

# Authentication Methods
def authenticate_with_msal(client_id, scopes, flow, username=None, password=None, refresh_token = None):
    try:
        authority = const.AUTHORITY_URL + "common"
        if globalargs.tenant_id != None:
            authority = const.AUTHORITY_URL + globalargs.tenant_id

        # Initialize PublicClientApplication
        app = msal.PublicClientApplication(
            client_id=client_id,
            authority=authority,
            http_client=sessions.auth_session
        )

        if flow == const.DEVICE_CODE_FLOW:
            # Start the device code flow
            flow = app.initiate_device_flow(scopes=scopes)

            # Print message to the user
            printer.print_info(flow['message'])

            # Acquire token using device code
            result = app.acquire_token_by_device_flow(flow)
        elif flow == const.ROPC_FLOW and username != None and password != None:
            result = app.acquire_token_by_username_password(username, password, scopes=const.SCOPE_MS_GRAPH)
        elif flow == const.REFRESH_TOKEN_FLOW and refresh_token != None:
            result = app.acquire_token_by_refresh_token(scopes=scopes, refresh_token=refresh_token)
        else:
            printer.print_error("Can not authenticate with the passed arguments")
            return

        # Check if the token was successfully acquired
        if 'access_token' in result:
            #printer.print_info(f"Got access token for resource {scopes} with client ID {client_id}")
            return result
        else:
            printer.print_error(result.get('error'))
            printer.print_error(result.get('error_description'))
            return
    except Exception as e:
        printer.print_error(f"Error on authenticating with MSAL: {e}")


#interactive auth to get NAA refresh token
def do_interactive_auth(url='https://portal.azure.com', upn=None, password=None, tenant_id = None):
    if tenant_id != None:
        url = url + f"/{tenant_id}"
    try:
        chrome_options = Options()
        chrome_options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
        #chrome_options.add_argument("--disable-infobars")
        #chrome_options.add_argument("--disable-web-security")
        #set user agent
        if globalargs.user_agent != None:
            chrome_options.add_argument(f"--user-agent={globalargs.user_agent}")
        else:
            chrome_options.add_argument(f"--user-agent={const.DEFAULT_USER_AGENT}")
        # add proxy
        if globalargs.proxy != None:
            chrome_options.add_argument(f"--proxy-server={globalargs.proxy}")
            # disable ssl verification when using proxy - beware!
            chrome_options.add_argument("--ignore-certificate-errors")
            chrome_options.add_argument("--ignore-certificate-errors-spki-list")
            chrome_options.add_argument("--allow-insecure-localhost")


        driver = webdriver.Chrome(options=chrome_options)
        driver.execute_cdp_cmd("Network.enable", {})
        time.sleep(1)
        #print(f"Navigate to {url} and complete login...")
        driver.get(url)
        # Wait until the page is fully loaded
        try:
            # Waiting for the presence of the 'Next' button on page
            element_present = EC.presence_of_element_located((By.ID, 'idSIButton9'))
            WebDriverWait(driver, 20).until(element_present)
        except TimeoutException:
            printer.print_error("Timeout while loading login!")
            sys.exit(1)

        if upn != None or password != None:
            auto_login(driver=driver,username=upn,password=password)
        responseBody = None
        try:
            while not responseBody:
                if is_session_closed(driver):
                    printer.print_error("Interactive authentication was closed by the user!")
                    sys.exit(1)
                time.sleep(0.1) # sleep between polling logs
                responseBody = find_refresh_token(driver)
        finally:
            driver.quit()

        if responseBody:
            printer.print_info(f"Acquired NAA Refresh Token (can be used with -naa for multiple runs): {responseBody["refresh_token"]}")
            return responseBody
        else:
            printer.print_error("Could not get tokens from authentication! Exiting...")
            sys.exit(1)
    except Exception as e:
        print(f"Error while performing interactive authentication: {e}")

#checks if driver session was closed
def is_session_closed(driver):
    try:
        # Try to access a simple property
        driver.title  # or driver.current_url
        return False  # Session is still open
    except WebDriverException:
        return True  # Session is closed (user closed it)

def find_refresh_token(driver):
    logs = driver.get_log("performance")
    for entry in logs:
        message = json.loads(entry["message"])["message"]
        if message["method"] == "Network.responseReceived":
            request_id = message["params"]["requestId"]
            try:
                response = driver.execute_cdp_cmd(
                    "Network.getResponseBody", {"requestId": request_id}
                )
                if "refresh_token" in response["body"]:
                    body = json.loads(response["body"])
                    return body
            except:
                pass
    return None

def auto_login(driver, username=None, password=None):
    wait = WebDriverWait(driver, 20)
    short_wait = WebDriverWait(driver, 3)
    # Enter username
    if username != None:
        try:
            email_input = wait.until(EC.presence_of_element_located((By.NAME, "loginfmt")))
            email_input.send_keys(username)
            time.sleep(1)
            driver.find_element(By.ID, "idSIButton9").click()  # Next
        except:
            pass
    time.sleep(1)
    # Enter password if password was supplied
    if password != None:
        try:
            password_input = wait.until(EC.presence_of_element_located((By.NAME, "passwd")))
            password_input.send_keys(password)
            time.sleep(1)
            driver.find_element(By.ID, "idSIButton9").click()  # Sign in
        except:
            pass
    # Handle "Stay signed in?" prompt
    try:
        heading = WebDriverWait(driver,2).until(EC.presence_of_element_located((By.XPATH, "//h1[contains(text(), 'Stay signed in')]")))
        if heading:
            stay_signed_in = short_wait.until(
            EC.element_to_be_clickable((By.ID, "idBtn_Back"))
            )
            stay_signed_in.click()
    except:
        pass  # Sometimes this prompt doesn't appear

# NAA Auth
def do_broker_authentication(refresh_token, client_id=const.ADIBIZAUX_CLIENT_ID, scope=const.SCOPE_MS_GRAPH, brk_client_id=const.AZURE_PORTAL_CLIENT_ID, redirect_uri=const.AZURE_PORTAL_BROKER_URI, origin=const.AZURE_PORTAL):
    # 74658136-14ec-4630-ad9b-26e160ff0fc6 is ADIbiziaUX
    # c44b4083-3bb0-49c1-b47d-974e53cbdf3c is Azure Portal
    body = {
    'client_id': client_id,
    'grant_type': 'refresh_token',
    'refresh_token': refresh_token,
    'scope': scope,
    'brk_client_id': brk_client_id,
    'redirect_uri': redirect_uri,
    }

    headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Origin': origin,
    }

    response = sessions.auth_session.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', data=body, headers=headers)
    if response.status_code != 200:
        print(f"Could not retrieve tokens via NAA auth. Dumping response: \n{response.content}")
        return None
    tokens = json.loads(response.text)
    return tokens
