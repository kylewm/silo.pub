import urllib.parse


def domain_for_url(url):
    p = urllib.parse.urlparse(url)
    return p.netloc


def trim_nulls(obj):
    if isinstance(obj, list):
        return [trim_nulls(v) for v in obj if trim_nulls(v)]
    if isinstance(obj, dict):
        return {k: trim_nulls(v) for k, v in obj.items()
                if trim_nulls(v)}
    return obj
