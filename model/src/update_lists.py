import io
import os
import urllib.request
import zipfile
from urllib.parse import urlparse

BASE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lists")
os.makedirs(BASE, exist_ok=True)


def download(url, timeout=180):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 PhisDetect/1.0"})
    return urllib.request.urlopen(req, timeout=timeout).read()


tranco_zip = download("https://tranco-list.eu/top-1m.csv.zip")
with zipfile.ZipFile(io.BytesIO(tranco_zip)) as z:
    name = z.namelist()[0]
    lines = z.read(name).decode("utf-8", "replace").splitlines()

hosts = []
for line in lines:
    parts = line.split(",")
    entry = (parts[1] if len(parts) >= 2 else parts[0]).strip().lower()
    if entry:
        hosts.append(entry)

with open(os.path.join(BASE, "tranco_top1m.txt"), "w") as f:
    f.write("\n".join(hosts))
with open(os.path.join(BASE, "tranco_top100k.txt"), "w") as f:
    f.write("\n".join(hosts[:100000]))

feed = download("https://openphish.com/feed.txt").decode("utf-8", "replace")
block_hosts = sorted({
    urlparse(u.strip()).netloc.lower()
    for u in feed.splitlines()
    if u.strip() and urlparse(u.strip()).netloc
})
with open(os.path.join(BASE, "openphish_hosts.txt"), "w") as f:
    f.write("\n".join(block_hosts))

print(f"tranco hosts: {len(hosts)}")
print(f"openphish hosts: {len(block_hosts)}")
