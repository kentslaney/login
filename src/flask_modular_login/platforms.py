from flask_dance.contrib.google import google, make_google_blueprint
from flask_dance.contrib.facebook import facebook, make_facebook_blueprint
from flask_dance.contrib.github import github, make_github_blueprint

import sys, os.path; end_locals, start_locals = lambda: sys.path.pop(0), (
    lambda x: x() or x)(lambda: sys.path.insert(0, os.path.dirname(__file__)))

from test import test, make_test_blueprint

end_locals()

methods = {
    "google": (google, make_google_blueprint, None),
    "facebook": (facebook, make_facebook_blueprint, None),
    "github": (github, make_github_blueprint, None),
    "test": (test, make_test_blueprint, None),
}

# returns {"id": "...", "name": "...", "picture": "..."}
def userlookup(method):
    if method == "google":
        return remap(google.get("/oauth2/v3/userinfo").json(), {
            "id": "sub", "name": "name", "picture": "picture"})
    elif method == "facebook":
        conf = ".width(200).height(200)"
        return remap(facebook.get(f"/me?fields=id,name,picture{conf}").json(), {
            "id": "id", "name": "name", "picture": ["picture", "data", "url"]})
    elif method == "github":
        return remap(github.get("/user").json(), {
            "id": "node_id", "name": "name", "picture": "avatar_url"})
    elif method == "test":
        return test.get()

# remapping to an array accesses nested dicts
def remap(old, mapping):
    res = {}
    for k, v in mapping.items():
        r = old
        for i in [v] if type(v) == str else v:
            r = r if r is None else r.get(i, None)
        res[k] = r
    return res
