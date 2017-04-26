import sys; sys.path.append('.')  # NOQA
from storage import StorageClient
from molotov import global_setup, set_var, get_var, scenario


@global_setup()
def set_token(args):
    set_var('client', StorageClient())


@scenario(1)
async def test(session):
    storage = get_var('client')
    url = "/info/collections"

    resp = await storage.get(session, url)
    assert resp.status in (200, 404)
