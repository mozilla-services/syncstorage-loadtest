import sys; sys.path.append('.')  # NOQA
import os
import base64
import time
import random
import json
from collections import defaultdict
from datetime import datetime
from pprint import pformat

import molotov

from storage import StorageClient, error_counts


_PAYLOAD = """\
This is the metaglobal payload which contains
some client data that doesnt look much
like this
"""
_WEIGHTS = {'metaglobal': [40, 60, 0, 0, 0],
            'distribution': [80, 15, 4, 1],
            'count_distribution': [71, 15, 7, 4, 3],
            'post_count_distribution': [67, 18, 9, 4, 2],
            'delete_count_distribution': [99, 1, 0, 0, 0]}

_PROBS = {'get': .1, 'post': .2, 'deleteall': 0.01}
_COLLS = ['bookmarks', 'forms', 'passwords', 'history', 'prefs']
_BATCH_MAX_COUNT = 100

_DISABLE_DELETES = (os.environ.get('DISABLE_DELETES', 'false').lower()
                    in ('true', '1'))
_LIMIT_COLLECTIONS = (os.environ.get('LIMIT_COLLECTIONS', 'true').lower()
                      in ('true', '1'))
_COL_LIMIT = 2 * 1000**3  # 2GB

session_stats = {}


def should_do(name):
    return random.random() <= _PROBS[name]


def get_num_requests(name):
    weights = _WEIGHTS[name]
    i = random.randint(1, sum(weights))
    count = 0
    base = 0
    for weight in weights:
        base += weight
        if i <= base:
            break
        count += 1
    return count


@molotov.setup_session()
async def _session(worker_num, session):
    exc = []

    def _run():
        try:
            session.storage = StorageClient(session)
        except Exception as e:
            exc.append(e)

    # XXX code will be migrated to Molotov
    # see https://github.com/loads/molotov/issues/100
    import threading
    t = threading.Thread(target=_run)
    t.start()
    t.join()
    if len(exc) > 0:
        raise exc[0]


@molotov.scenario(1)
async def test(session):
    storage = session.storage
    #print('ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ %s %s %s' %
    #      (id(session), storage.uid, storage.write_counts))
    if _LIMIT_COLLECTIONS:
        for col, write_count in list(storage.write_counts.items()):
            if write_count > _COL_LIMIT:
                print('RRRRRESET %s %s %s %s' %
                      (datetime.now().isoformat(),
                       storage.uid,
                       storage.write_counts,
                       error_counts))
                session.storage.generate()
                storage.write_counts.clear()

    # Respect the server limits.
    _, config = await storage.get("/info/configuration")
    # print("Config: {}".format(json.dumps(config, indent=3)))
    # fix up consts
    payload = _PAYLOAD[:config.get("max_record_payload_bytes")]
    # GET requests to meta/global
    num_requests = min(get_num_requests('metaglobal'),
                       config.get("max_post_records"))
    batch_max_count = min(_BATCH_MAX_COUNT, config.get("max_total_records"))

    # Always GET info/collections
    # This is also a good opportunity to correct for timeskew.
    url = "/info/collections"
    resp, _ = await storage.get(url, (200, 404))

    url = "/storage/meta/global"

    for x in range(num_requests):
        resp, __ = await storage.get(url, (200, 404))
        if resp.status == 404:
            data = json.dumps({"id": "global", "payload": payload})
            await storage.put(url, data=data, statuses=(200,))

    # Occasional reads of client records.
    if should_do('get'):
        url = "/storage/clients"
        newer = int(time.time() - random.randint(3600, 360000))
        params = {"full": "1", "newer": str(newer)}
        await storage.get(url, params=params, statuses=(200, 404))

    # Occasional updates to client records.
    if should_do('post'):
        cid = str(get_num_requests('distribution'))
        url = "/storage/clients"
        payload = cid * 300
        payload_length = len(payload)
        wbo = {'id': 'client' + cid, 'payload': payload}
        data = json.dumps([wbo])
        resp, result = await storage.post(url, data=data, statuses=(200,))
        assert len(result["success"]) == 1, "No success records"
        assert len(result["failed"]) == 0, "Found failed record"
        storage.write_counts['clients'] += payload_length

    # GET requests to individual collections.
    num_requests = get_num_requests('count_distribution')
    cols = random.sample(_COLLS, num_requests)
    for x in range(num_requests):
        url = "/storage/" + cols[x]
        newer = int(time.time() - random.randint(3600, 360000))
        params = {"full": "1", "newer": str(newer)}
        await storage.get(url, params=params, statuses=(200, 404))

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

    payload_lengths = defaultdict(int)
    for x in range(num_requests):
        col = cols[x]
        url = "/storage/" + col
        data = []
        # Random batch size, skewed slightly towards the upper limit.
        items_per_batch = min(random.randint(20, batch_max_count + 80),
                              batch_max_count)
        for _i in range(items_per_batch):
            randomness = os.urandom(10)
            bso_id = base64.urlsafe_b64encode(randomness).rstrip(b"=")
            bso_id = bso_id.decode('utf8')
            bso_id += str(int((time.time() % 100) * 100000))
            # Random payload length.  They can be big, but skew small.
            # This gives min=300, mean=450, max=config.max_record_payload_bytes
            payload_length = min(
                int(random.paretovariate(3) * 300),
                config.get("max_record_payload_bytes"))
            payload_lengths[col] += payload_length

            # XXX should be in the class
            token = storage.auth_token.decode('utf8')
            payload_chunks = int((payload_length / len(token)) + 1)
            payload = (token * payload_chunks)[:payload_length]
            wbo = {'id': bso_id, 'payload': payload}
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

        resp, result = await storage.post(url, data=data, statuses=(status,))
        assert len(result["success"]) == items_per_batch, (
            "Result success did not have expected number of"
            "items in batch {}".format(result)
        )
        assert len(result["failed"]) == 0, (
            "Result contained failed records: {}".format(result)
        )

        if not transact or committing:
            for col, payload_length in payload_lengths.items():
                storage.write_counts[col] += payload_length
            payload_lengths.clear()

        if transact and not committing:
            batch_id = result["batch"]

    if not _DISABLE_DELETES:
        # DELETE requests.
        # We might choose to delete some individual collections, or to
        # do a full reset and delete all the data.  Never both in the
        # same run.
        num_requests = get_num_requests('delete_count_distribution')
        if num_requests:
            cols = random.sample(_COLLS, num_requests)
            for x in range(num_requests):
                url = "/storage/" + cols[x]
                resp, result = await storage.delete(url, statuses=(200, 204))
        else:
            if should_do('deleteall'):
                url = "/storage"
                resp, result = await storage.delete(url, statuses=(200,))


@molotov.teardown_session()
async def save_session_stats(worker_num, session):
    session_stats[worker_num] = session.storage.write_counts


@molotov.global_teardown()
def print_stats():
    #if session.args.verbose:
    for worker_num, write_counts in session_stats.items():
        print("Session write_counts ({}): {}".format(
            worker_num,
            pformat(sorted(write_counts.items()))
        ))
    print("Error codes: {}".format(pformat(sorted(error_counts.items()))))
