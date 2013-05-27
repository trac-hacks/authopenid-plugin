"""
"""

from urlparse import urljoin, urlparse, urlunparse

def sanitize_referer(referer, base_url):
    """ Ensure that ``referer`` is 'under' ``base_url``.

    This interprets ``referer`` relative to ``base_url``.  Any anchor or
    query is removed.

    Returns a normalized absolute version of ``referer`` if it refers
    to a URL which is or is 'under' ``base_url``; otherwise returns ``None``.

    """
    if referer is None:
        return None
    abs_referer = urljoin(base_url, referer)
    base = urlparse(base_url)
    assert base.scheme and base.netloc

    # make absolute
    ref = urlparse(abs_referer)
    if (ref.scheme, ref.netloc) != (base.scheme, base.netloc):
        return None


    split_path = split_path_info(ref.path)
    if ref.path.endswith('/'):
        split_path.append('')
    base_path = split_path_info(base.path)

    if split_path[:len(base_path)] != base_path:
        return None
    return urlunparse((ref.scheme, ref.netloc, '/'.join(split_path),
                       None, None, None))

def split_path_info(path):
    assert path.startswith('/')
    clean = []
    for segment in path.split('/'):
        if segment and segment != '.':
            if segment == '..':
                if clean:
                    del clean[-1]
            else:
                clean.append(segment)
    return [''] + clean
