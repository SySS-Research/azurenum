from azurenum.utils import const
import requests
# Start global session for msal and python-requests
# Need to patch the prepare_request method to remove the x-client-os header that msal sets
class PatchedSession(requests.Session):
    def prepare_request(self, request, *args, **kwargs):
        # Call the parent class's prepare_request method
        request = super().prepare_request(request, *args, **kwargs)
        
        # Remove the unwanted header if it exists
        if "x-client-os" in request.headers:
            del request.headers["x-client-os"]
        
        return request

auth_session = PatchedSession()
auth_session.headers.update({"User-Agent": const.DEFAULT_USER_AGENT})

query_session = requests.session()
query_session.headers = {'User-Agent': const.DEFAULT_USER_AGENT}
