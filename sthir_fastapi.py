"""OPTIONAL FastAPI front for the Sthir offline hub. Same router as `sthir_offline.py serve`.

Run:  pip install fastapi uvicorn   then   uvicorn sthir_fastapi:app --port 5101
On Termux, fastapi needs pydantic-core, which often fails to build. If it does, use the
built-in server instead (`python sthir_offline.py serve`): it exposes the same routes.
"""
import os

from fastapi import Body, FastAPI, HTTPException

import sthir_offline as O

os.makedirs("sthir-offline", exist_ok=True)
hub = O.Hub("sthir-offline/hub.json")
route = O.make_router(hub, O.Relay(), allow_credit=False)
app = FastAPI(title="Sthir offline node")


def call(path: str, body: dict):
    try:
        return route(path, body)
    except KeyError:
        raise HTTPException(404, "not found")
    except (O.HubError, ValueError, TypeError, AttributeError) as e:
        raise HTTPException(400, str(e) or "bad request")


@app.get("/status")
def status():
    return call("/status", {})


def _add(path: str):
    def handler(body: dict = Body(...)):
        return call(path, body)
    handler.__name__ = "post_" + path.strip("/").replace("/", "_")
    app.post(path)(handler)


for _p in ("/voucher/lock", "/voucher/redeem", "/voucher/check", "/voucher/status", "/verify/samples", "/relay/put", "/relay/get"):
    _add(_p)
