import sys; sys.path.append('.')  # NOQA
import time
import random
import json

from storage import StorageClient
from molotov import global_setup, set_var, get_var, scenario


_PAYLOAD = """\
This is the metaglobal payload which contains
some client data that doesnt look much
like this
"""
_WEIGHTS = {'metaglobal': [40, 60, 0, 0, 0],
            'distribution': [80, 15, 4, 1]}
_PROBS = {'get': .1, 'post': .2}


def should_do(name):
    return random.random() <= _PROBS[name]


def get_num_requests(name):
    weights = _WEIGHTS['metaglobal']
    i = random.randint(1, sum(weights))
    count = 0
    base = 0
    for weight in weights:
        base += weight
        if i <= base:
            break
        count += 1
    return count


@global_setup()
def set_token(args):
    set_var('client', StorageClient())


@scenario(1)
async def test(session):
    storage = get_var('client')

    # Always GET info/collections
    # This is also a good opportunity to correct for timeskew.
    url = "/info/collections"
    await storage.get(session, url, (200, 404))

    # GET requests to meta/global
    num_requests = get_num_requests('metaglobal')
    for x in range(num_requests):
        url = "/storage/meta/global"
        resp = await storage.get(session, url, (200, 404))

        if resp.status == 404:
            data = json.dumps({"id": "global", "payload": _PAYLOAD})
            await storage.put(session, url, data=data, statuses=(200,))

    # Occasional reads of client records.
    if should_do('get'):
        url = "/storage/clients"
        newer = int(time.time() - random.randint(3600, 360000))
        params = {"full": "1", "newer": str(newer)}
        resp = await storage.get(session, url, params=params,
                                 statuses=(200, 404))

    # Occasional updates to client records.
    if should_do('post'):
        cid = str(get_num_requests('distribution'))
        url = "/storage/clients"
        wbo = {'id': 'client' + cid, 'payload': cid * 300}
        data = json.dumps([wbo])
        resp = await storage.post(session, url, data=data, statuses=(200,))
        result = await resp.json()
        assert len(result["success"]) == 1
        assert len(result["failed"]) == 0
