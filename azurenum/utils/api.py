from azurenum.utils import const,printer, sessions
import json


## handler that deals with inconsistent use of True/"true"/"True" and False/"False"/"false" in json objects from microsoft APIs.
def convert_bool_values(data):
    """
    Recursively walk through JSON-like data (dict, list, or primitive)
    and convert string representations of booleans to actual Python booleans.
    
    Converts:
        "true" → True
        "True" → True
        "TRUE" → True
        "false" → False
        "False" → False
        "FALSE" → False
        (actual bool) → unchanged
        (other types) → unchanged
    """
    if isinstance(data, dict):
        return {key: convert_bool_values(value) for key, value in data.items()}
    
    elif isinstance(data, list):
        return [convert_bool_values(item) for item in data]
    
    elif isinstance(data, str):
        # Normalize string booleans
        if data.strip().lower() == "true":
            return True
        elif data.strip().lower() == "false":
            return False
        elif data.strip().lower() == "none":
            return None
        else:
            return data  # return unchanged if not a boolean string
    
    else:
        # Already a bool, int, float, None, etc. → leave as-is
        return data

#### Request Methods ###
# Return JSON object from response on succes or 'None' on error

#get data from MSGraph ('https://graph.microsoft.com')
def get_msgraph(endpoint, params, token, version="v1.0"):
    headers = {
        "Authorization": f"Bearer {token}"
    }

    url = const.MS_GRAPH_API + "/" + version + endpoint
    r = sessions.query_session.get(url, params=params, headers=headers)
    result = convert_bool_values(json.loads(r.text))
    
    # Check request worked
    if "@odata.context" not in result:
        printer.print_error(f"Could not fetch URL: {r.url}")
        return

    return result

#get data from MSGraph ('https://graph.microsoft.com')
def get_msgraph_value(endpoint, params, token, version="v1.0"):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    url = const.MS_GRAPH_API + "/" + version + endpoint
    results = []

    while True:
        r = sessions.query_session.get(url, params=params, headers=headers)
        rawResult = json.loads(r.text)

        # Check request worked
        if "@odata.context" not in rawResult:
            printer.print_error(f"Could not fetch URL: {r.url}")
            return
        
        # Add results
        results.extend(convert_bool_values(rawResult["value"]))

        # If no nextLink present, break and return
        if "@odata.nextLink" not in rawResult:
            break
        else:
            url = rawResult["@odata.nextLink"]
            params = {} # nextLink includes the search params
    
    return results

# post data to msgraph. currently only used to resolve ids (helper:resolve_directoryObjects_byIds)
def post_msgraph(endpoint, params, token, data, version = "v1.0"):
    headers = {
        "Authorization": f"Bearer {token}"
    }

    url = const.MS_GRAPH_API + "/" + version + endpoint
    r = sessions.query_session.post(url, params=params, headers=headers, json=data)
    result = convert_bool_values(json.loads(r.text))
    # print(f"DEBUG: {result}")
    # Check request worked
    if "@odata.context" not in result:
        printer.print_error(f"Could not fetch URL: {r.url}")
        return

    return result


# get data from AADGraph internal API ('https://graph.windows.net') -- deprecated
def get_aadgraph(endpoint, params, tenantId, token, apiVersion = "1.61-internal"):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    url = f"{const.AAD_GRAPH_API}/{tenantId}{endpoint}"
    params["api-version"] = apiVersion
    r = sessions.query_session.get(url, params=params, headers=headers)
    result = convert_bool_values(json.loads(r.text))
    
    # Check request worked
    if "odata.metadata" not in result:            
        printer.print_error(f"Could not fetch URL: {r.url}")
        return

    return result


# get data from AADGraph internal API ('https://graph.windows.net') -- deprecated
def get_aadgraph_value(endpoint, params, tenantId, token, apiVersion = "1.61-internal"):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    url = f"{const.AAD_GRAPH_API}/{tenantId}{endpoint}"
    results = []
    params["api-version"] = apiVersion
    while True:
        r = sessions.query_session.get(url, params=params, headers=headers)
        rawResult = convert_bool_values(json.loads(r.text))
        
        # Check request worked
        if "odata.metadata" not in rawResult:            
            printer.print_error(f"Could not fetch URL: {r.url}")
            return
        
        # Add results
        results.extend(rawResult["value"])

        # If no nextLink present, break and return
        if "odata.nextLink" not in rawResult:
            break
        else:
            nextLink = rawResult["odata.nextLink"]
            url = f"{const.AAD_GRAPH_API}/{tenantId}/{nextLink}&api-version={apiVersion}"
            params = {} # nextLink includes the search params

    return results


# get data from ARM ('https://management.azure.com' )
def get_arm(endpoint, params, token, apiVersion = "2018-02-01"):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    url = const.ARM_API + endpoint
    params["api-version"] = apiVersion
    r = sessions.query_session.get(url, params=params, headers=headers)
    result = convert_bool_values(json.loads(r.text))

    if r.status_code != 200:
        printer.print_error(f"Could not fetch URL: {r.url}")
        return

    return result


# get data from 'https://main.iam.ad.ext.azure.com'
def get_main_iam(endpoint, params, token):
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Ms-Client-Request-Id": "00000000-0000-0000-0000-000000000000" # can be any uuid
    }
    url = const.MAIN_IAM_API + "/api/" +  endpoint
    # print(f"querying data from {url} with params {params}.\n using auth: {headers}")
    r = sessions.query_session.get(url, params=params, headers=headers)
    # print(r)
    # Check request worked
    if r.status_code != 200:
        printer.print_error(f"Could not fetch URL: {r.url}")
        print(r.text)
        return
    result = convert_bool_values(json.loads(r.text))
    return result


# get data from 'https://main.iam.ad.ext.azure.com'
def get_main_iam_value(endpoint, params, token):
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Ms-Client-Request-Id": "00000000-0000-0000-0000-000000000000" # can be any uuid
    }
    url = const.MAIN_IAM_API + "/api/"  + endpoint
    results = []
    while True:
        r = sessions.query_session.get(url, params=params, headers=headers)
        rawResult = convert_bool_values(json.loads(r.text))
        
        # Check request worked
        if "@odata.context" not in rawResult:
            printer.print_error(f"Could not fetch URL: {r.url}")
            return
        
        # Add results
        results.extend(rawResult["value"])

        # If no nextLink present, break and return
        if "@odata.nextLink" not in rawResult:
            break
        else:
            url = rawResult["@odata.nextLink"]
            params = {} # nextLink includes the search params

    return results
