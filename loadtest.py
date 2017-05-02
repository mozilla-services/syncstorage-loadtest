import sys; sys.path.append('.')  # NOQA
import os
import base64
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
            'distribution': [80, 15, 4, 1],
            'count_distribution': [71, 15, 7, 4, 3],
            'post_count_distribution': [67, 18, 9, 4, 2]}

_PROBS = {'get': .1, 'post': .2}
_COLLS = ['bookmarks', 'forms', 'passwords', 'history', 'prefs']
_BATCH_MAX_COUNT = 100


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
    url = "/storage/meta/global"

    for x in range(num_requests):
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

    # GET requests to individual collections.
    num_requests = get_num_requests('count_distribution')
    cols = random.sample(_COLLS, num_requests)
    for x in range(num_requests):
        url = "/storage/" + cols[x]
        newer = int(time.time() - random.randint(3600, 360000))
        params = {"full": "1", "newer": str(newer)}
        resp = await storage.get(session, url, params=params, statuses=(200, 404))


    # POST requests with several WBOs batched together
    num_requests = get_num_requests('post_count_distribution')
    # Let's do roughly 50% transactional batches.
    transact = random.randint(0, 1)
    batch_id = None
    committing = False

    # Collections should be a single static entry if we're "transactional"
    if transact:
        col = random.sample(_COLLS, 1)[0]
        cols = [col for x in range(num_requests)]
    else:
        cols = random.sample(_COLLS, num_requests)

    for x in range(num_requests):
        url = "/storage/" + cols[x]
        data = []
        # Random batch size, skewed slightly towards the upper limit.
        items_per_batch = min(random.randint(20, _BATCH_MAX_COUNT + 80),
                              _BATCH_MAX_COUNT)
        for i in range(items_per_batch):
            randomness = os.urandom(10)
            id = str(base64.urlsafe_b64encode(randomness).rstrip(b"="))
            id += str(int((time.time() % 100) * 100000))
            # Random payload length.  They can be big, but skew small.
            # This gives min=300, mean=450, max=7000
            payload_length = min(int(random.paretovariate(3) * 300), 7000)

            # XXX should be in the class
            token = str(storage.auth_token)
            payload_chunks = int((payload_length / len(token)) + 1)
            payload = (token * payload_chunks)[:payload_length]
            wbo = {'id': id, 'payload': payload}
            data.append(wbo)

        data = json.dumps(data)
        status = 200
        if transact:
            # Batch uploads only return a 200 on commit.  An Accepted(202)
            # is returned for batch creation & appends
            status = 202
            if x == 0:
                committing = False
                url += "?batch=true"
            elif x == num_requests - 1:
                url += "?commit=true&batch=%s" % batch_id
                committing = True
                batch_id = None
                status = 200
            else:
                url += "?batch=%s" % batch_id

        resp = await storage.post(session, url, data=data, statuses=(status,))
        result = await resp.json()
        assert len(result["success"]) == items_per_batch, result
        assert len(result["failed"]) == 0, result

        if transact and not committing:
            batch_id = result["batch"]
