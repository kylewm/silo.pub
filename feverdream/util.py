import urllib.parse


def domain_for_url(url):
    p = urllib.parse.urlparse(url)
    return p.netloc
