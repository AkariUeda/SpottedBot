from urllib.parse import urlparse
import json
import requests
from django.conf import settings


def is_safe(url):
    """Is Safe.

    returns true if google and wot safe
    false otherwise
    """
    # Domain white lists
    white_list = [
        "http://i.imgur.com/",
        "https://i.imgur.com/",
    ]

    def is_whitelist(url):
        for domain in white_list:
            if url.startswith(domain):
                return True
        return False

    if is_whitelist(url):
        return True

    if settings.WOT_SECRET and not is_WOT_safe(url):
        return False

    if settings.GSB_SECRET and not is_google_safe(url):
        return False

    return True


def is_WOT_safe(url):
    """WOT API Wrapper.

    calls the api and checks for high levels of safety confidence
    """
    secret = settings.WOT_SECRET
    user = settings.WOT_USER
    # make sure that the last char is a '/'
    parsed_url = "{uri.scheme}://{uri.netloc}/".format(uri=urlparse(url))
    payload = {"t": parsed_url}
    response = requests.get(
        "https://scorecard.api.mywot.com/v3/targets?t=example.com&t=example.com",
        params=payload,
        headers={"x-user-id": user, "x-api-key": secret},
    )

    data = response.json()

    if (not data or len(data) == 0) and response.status_code == requests.codes.ok:
        return True

    return data[0]["safety"]["status"] == "SAFE"


def is_google_safe(url):
    """Google Safe Browsing Wrapper.

    calls api, checks all lists and returns true if not found in any list
    false otherwise
    """
    secret = settings.GSB_SECRET
    params = {"key": secret}
    payload = json.dumps(
        {
            "client": {"clientId": "spottedsystem", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                    "MALICIOUS_BINARY",
                    "UNWANTED_SOFTWARE",
                ],
                "platformTypes": [
                    "ANY_PLATFORM",
                    "WINDOWS",
                    "LINUX",
                    "OSX",
                    "ANDROID",
                    "CHROME",
                    "IOS",
                ],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": url},
                ],
            },
        }
    )

    response = requests.post(
        "https://safebrowsing.googleapis.com/v4/threatMatches:find",
        params=params,
        data=payload,
    )

    return not response.json() and response.status_code == requests.codes.ok
