"""Sthir network layer v0.1

Runs a real Sthir node over HTTP (stdlib only) on top of sthir.py:
  - gossip: new blocks and transactions are relayed to peers
  - peer discovery: peers are learned from seeds, senders and /peers
  - sync: a node behind (or that missed a block) pulls the heavier chain
  - optional mining thread, wallet files, send/balance/status commands

Usage (see `python sthir_net.py -h`):
  python sthir_net.py demo
  python sthir_net.py wallet new
  python sthir_net.py node --port 5001 --mine wallet.key
  python sthir_net.py node --port 5002 --peer http://127.0.0.1:5001
  python sthir_net.py send --node http://127.0.0.1:5001 --key wallet.key --to ADDR --amount 5

Prototype only: no authentication and no rate limiting. Run it on a trusted network.
The chain is saved under ./sthir-data/<port> (see --data) and survives restarts.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sthir import (
    UNIT, Block, InvalidBlock, Node, Params, Tx, Wallet, block_reward,
    meets_difficulty,
)

MAX_BODY = 8 * 1024 * 1024
POLL_SECONDS = 8


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


# ------------------------------------------------------------ serialization
def tx_to_dict(t: Tx) -> dict:
    return {"sender": t.sender, "recipient": t.recipient, "amount": t.amount,
            "fee": t.fee, "nonce": t.nonce, "signature": t.signature}


def tx_from_dict(d: dict) -> Tx:
    return Tx(str(d["sender"]), str(d["recipient"]), int(d["amount"]),
              int(d["fee"]), int(d["nonce"]), str(d.get("signature", "")))


def block_to_dict(b: Block) -> dict:
    return {"height": b.height, "prev_hash": b.prev_hash, "timestamp": b.timestamp,
            "miner": b.miner, "reward": b.reward,
            "txs": [tx_to_dict(t) for t in b.txs], "nonce": b.nonce}


def block_from_dict(d: dict) -> Block:
    return Block(int(d["height"]), str(d["prev_hash"]), int(d["timestamp"]),
                 str(d["miner"]), int(d["reward"]),
                 [tx_from_dict(t) for t in d["txs"]], int(d["nonce"]))


# ------------------------------------------------------------------ wallets
def new_wallet(path: str) -> Wallet:
    if os.path.exists(path):
        raise SystemExit(f"{path} already exists; refusing to overwrite a key")
    sk = Ed25519PrivateKey.generate()
    raw = sk.private_bytes(serialization.Encoding.Raw,
                           serialization.PrivateFormat.Raw,
                           serialization.NoEncryption())
    with open(path, "w") as f:
        f.write(raw.hex())
    os.chmod(path, 0o600)
    return Wallet(sk)


def load_wallet(path: str) -> Wallet:
    with open(path) as f:
        raw = bytes.fromhex(f.read().strip())
    return Wallet(Ed25519PrivateKey.from_private_bytes(raw))


def resolve_address(value: str) -> str:
    """A key file path or a 64-hex address."""
    if os.path.exists(value):
        return load_wallet(value).address
    if len(value) == 64:
        bytes.fromhex(value)
        return value
    raise SystemExit(f"'{value}' is neither a key file nor a 64-hex address")


# --------------------------------------------------------------------- http
def http_get(url: str, timeout: float = 5):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read())


def http_post(url: str, obj, timeout: float = 5):
    req = urllib.request.Request(
        url, json.dumps(obj).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def valid_url(u) -> bool:
    return isinstance(u, str) and u.startswith(("http://", "https://")) and len(u) < 200


# ---------------------------------------------------------------- net node
class ChainStore:
    """Keeps the chain on disk so it survives restarts.

    <dir>/meta.json    the chain rules the data was created with
    <dir>/chain.jsonl  one block per line, in order

    Blocks are appended as they are accepted; after a reorg the whole file is
    rewritten atomically. On start the chain is loaded and fully re-validated,
    so a damaged or edited file can never put invalid coins on the chain.
    """

    def __init__(self, path: str, rules: list):
        self.dir, self.rules = path, rules
        self.chain_file = os.path.join(path, "chain.jsonl")
        self.meta_file = os.path.join(path, "meta.json")
        os.makedirs(path, exist_ok=True)

    @staticmethod
    def _atomic_write(path: str, text: str) -> None:
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    def _ensure_meta(self) -> None:
        if not os.path.exists(self.meta_file):
            self._atomic_write(self.meta_file, json.dumps({"rules": self.rules}))

    def load(self) -> list[Block]:
        if os.path.exists(self.meta_file):
            with open(self.meta_file) as f:
                saved = json.load(f).get("rules")
            if saved != self.rules:
                raise SystemExit(
                    f"{self.dir} holds a chain made with rules {saved}, but this "
                    f"node uses {self.rules}. Use the same rules, or another --data folder.")
        else:
            self._ensure_meta()
        if not os.path.exists(self.chain_file):
            return []
        with open(self.chain_file, "rb") as f:
            raw = f.read()
        blocks: list[Block] = []
        good = 0
        for line in raw.splitlines(keepends=True):
            try:
                if not line.endswith(b"\n"):
                    raise ValueError("unfinished line")
                blocks.append(block_from_dict(json.loads(line)))
            except (ValueError, KeyError, TypeError):
                if good + len(line) == len(raw):  # only the last line can be torn
                    log(f"dropping an unfinished last line in {self.chain_file}")
                    with open(self.chain_file, "r+b") as f:
                        f.truncate(good)
                    break
                raise SystemExit(
                    f"{self.chain_file} is damaged at block {len(blocks) + 1}. "
                    "Move that folder aside to start fresh.")
            good += len(line)
        return blocks

    def append(self, block: Block) -> None:
        self._ensure_meta()
        line = json.dumps(block_to_dict(block), separators=(",", ":")) + "\n"
        with open(self.chain_file, "ab") as f:
            f.write(line.encode())
            f.flush()
            os.fsync(f.fileno())

    def rewrite(self, blocks: list[Block]) -> None:
        self._ensure_meta()
        self._atomic_write(self.chain_file, "".join(
            json.dumps(block_to_dict(b), separators=(",", ":")) + "\n" for b in blocks))


class NetNode:
    def __init__(self, params: Params, url: str, miner: str | None):
        self.node = Node(params, url)
        self.url = url.rstrip("/")
        self.miner = miner
        self.lock = threading.RLock()
        self.peers: set[str] = set()
        self.rejected: set[str] = set()  # peers running different chain rules
        self.store: ChainStore | None = None
        self.known = {self.node.genesis.hash()}
        self.stop = threading.Event()
        self.mine_later = False   # start idle; a wallet app on this device sets the address
        self.miner_started = miner is not None
        self.mining = True        # the on/off switch; the wallet app flips it
        self.pause_file: str | None = None
        self.vault_dir: str | None = None   # where sealed account backups are kept
        self.vaults: dict[str, str] = {}
        self.vault_hits: dict[str, list[float]] = {}

    def _refresh_known(self):
        self.known = {b.hash() for b in self.node.chain}

    def set_miner(self, addr) -> str:
        """Point mining rewards at another address (used when the wallet changes)."""
        if not (isinstance(addr, str) and len(addr) == 64):
            raise ValueError("bad address")
        bytes.fromhex(addr)
        with self.lock:
            if self.miner is None and not self.mine_later:
                raise ValueError("this node is not mining")
            self.miner = addr.lower()
            start = not self.miner_started
            self.miner_started = True
        if start:
            threading.Thread(target=self.miner_loop, daemon=True).start()
        log(f"mining now pays to {addr[:12]}...")
        return self.miner

    def set_mining(self, on) -> bool:
        """Switch mining on or off without stopping the node."""
        on = bool(on)
        with self.lock:
            if on and self.miner is None:
                raise ValueError("No wallet is set to receive coins yet. Log in first.")
            self.mining = on
            start = on and not self.miner_started
            if start:
                self.miner_started = True
        if self.pause_file:
            try:
                if on and os.path.exists(self.pause_file):
                    os.remove(self.pause_file)
                elif not on:
                    open(self.pause_file, "w").close()
            except OSError:
                pass
        if start:
            threading.Thread(target=self.miner_loop, daemon=True).start()
        log("mining " + ("on" if on else "off"))
        return on

    # ---- sealed account backups. The node cannot read them: they are encrypted with
    # the owner's password, and the id they live under is derived from it.
    VAULT_MAX = 4096
    VAULT_LIMIT = 5000

    def _vault_rate_ok(self, ip: str) -> bool:
        now = time.time()
        with self.lock:
            hits = [t for t in self.vault_hits.get(ip, []) if now - t < 60]
            hits.append(now)
            self.vault_hits[ip] = hits
            if len(self.vault_hits) > 2000:
                self.vault_hits = {k: v for k, v in self.vault_hits.items() if v and now - v[-1] < 60}
            return len(hits) <= 20

    def vault_get(self, vid: str):
        if not (len(vid) == 64 and all(c in "0123456789abcdef" for c in vid)):
            raise ValueError("bad id")
        with self.lock:
            if vid in self.vaults:
                return self.vaults[vid]
        if self.vault_dir:
            try:
                with open(os.path.join(self.vault_dir, vid)) as f:
                    return f.read()
            except OSError:
                pass
        return None

    def vault_put(self, vid: str, blob) -> None:
        if not (len(vid) == 64 and all(c in "0123456789abcdef" for c in vid)):
            raise ValueError("bad id")
        if not isinstance(blob, str) or not blob.startswith("sthir-vault:") or len(blob) > self.VAULT_MAX:
            raise ValueError("not a sealed Sthir backup")
        with self.lock:
            if vid not in self.vaults and len(self.vaults) >= self.VAULT_LIMIT:
                raise ValueError("this relay is full")
            self.vaults[vid] = blob
        if self.vault_dir:
            os.makedirs(self.vault_dir, mode=0o700, exist_ok=True)
            tmp = os.path.join(self.vault_dir, vid + ".tmp")
            with open(tmp, "w") as f:
                f.write(blob)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, os.path.join(self.vault_dir, vid))

    def _save_block(self, block: Block):
        if self.store:
            try:
                self.store.append(block)
            except OSError as e:
                log(f"WARNING: could not save block {block.height}: {e}")

    def _save_all(self):
        if self.store:
            try:
                self.store.rewrite(self.node.chain[1:])
            except OSError as e:
                log(f"WARNING: could not save the chain: {e}")

    def load_saved(self):
        blocks = self.store.load()
        if not blocks:
            log(f"no saved chain in {self.store.dir}; starting from genesis")
            return
        try:
            self.node.adopt_chain(blocks)
        except InvalidBlock as e:
            raise SystemExit(f"The saved chain in {self.store.dir} is invalid ({e}). "
                             "Move that folder aside to start fresh.")
        self._refresh_known()
        log(f"loaded {len(blocks)} saved blocks; chain is at height {self.node.tip.height}")

    def rules(self) -> list:
        p = self.node.p
        return [p.difficulty_bits, p.target_block_time, p.retarget_interval]

    def rules_match(self, url: str, st: dict) -> bool:
        """Peers with different consensus rules can never agree; skip them."""
        if st.get("rules") == self.rules():
            return True
        log(f"peer {url} runs different rules {st.get('rules')} "
            f"(ours {self.rules()}); ignoring it")
        with self.lock:
            self.peers.discard(url)
            self.rejected.add(url)
        return False

    # ---------------------------------------------------------------- peers
    def add_peer(self, url) -> bool:
        if not valid_url(url):
            return False
        url = url.rstrip("/")
        with self.lock:
            if url == self.url or url in self.peers or url in self.rejected:
                return False
            self.peers.add(url)
        log("peer added:", url)
        return True

    def broadcast(self, path: str, payload, exclude: str | None = None):
        with self.lock:
            targets = [p for p in self.peers if p != exclude]
        for p in targets:
            threading.Thread(target=self._post_quiet, args=(p + path, payload),
                             daemon=True).start()

    @staticmethod
    def _post_quiet(url, payload):
        try:
            http_post(url, payload)
        except Exception:
            pass

    # --------------------------------------------------------------- inbound
    def receive_block(self, bd: dict, sender) -> str:
        block = block_from_dict(bd)
        h = block.hash()
        sender = sender.rstrip("/") if valid_url(sender) else None
        if sender:
            self.add_peer(sender)
        with self.lock:
            if h in self.known:
                return "known"
            tip = self.node.tip
            extends = block.prev_hash == tip.hash()
            if extends:
                self.node.add_block(block)  # InvalidBlock -> caller returns 400
                self.known.add(h)
                self._save_block(block)
        if extends:
            log(f"block {block.height} accepted ({h[:10]}) from {sender or 'unknown'}")
            self.broadcast("/block", {"block": bd, "from": self.url}, exclude=sender)
            return "accepted"
        if block.height > tip.height and sender:
            threading.Thread(target=self.sync_from_peer, args=(sender,),
                             daemon=True).start()
            return "syncing"
        return "stale"

    def receive_tx(self, td: dict) -> str:
        tx = tx_from_dict(td)
        tid = tx.txid()
        with self.lock:
            if any(t.txid() == tid for t in self.node.mempool):
                return "known"
            self.node.submit_tx(tx)  # InvalidBlock -> caller returns 400
        log(f"tx {tid[:10]} accepted into mempool")
        self.broadcast("/tx", td)
        return "accepted"

    # ------------------------------------------------------------------ sync
    def sync_from_peer(self, url: str) -> bool:
        try:
            data = http_get(url + "/chain", timeout=30)
            blocks = [block_from_dict(d) for d in data]
            with self.lock:
                switched = self.node.adopt_chain(blocks)
                if switched:
                    self._refresh_known()
                    self._save_all()
                    height = self.node.tip.height
            if switched:
                log(f"synced from {url}: now at height {height}")
            return switched
        except InvalidBlock as e:
            log(f"peer {url} sent an invalid chain: {e}")
        except Exception as e:
            log(f"sync from {url} failed: {e}")
        return False

    def poll_loop(self):
        while not self.stop.wait(POLL_SECONDS):
            with self.lock:
                peers = list(self.peers)
            for p in peers:
                try:
                    st = http_get(p + "/status", timeout=4)
                    if not self.rules_match(p, st):
                        continue
                    with self.lock:
                        mine = self.node.total_work()
                    if int(st["work"]) > mine:
                        self.sync_from_peer(p)
                    for q in http_get(p + "/peers", timeout=4)["peers"]:
                        self.add_peer(q)
                except Exception:
                    pass

    def connect_seed(self, seed: str):
        seed = seed.rstrip("/")
        if not self.add_peer(seed):
            return
        try:
            if not self.rules_match(seed, http_get(seed + "/status")):
                return
            http_post(seed + "/peer", {"url": self.url})
            for q in http_get(seed + "/peers")["peers"]:
                self.add_peer(q)
        except Exception as e:
            log(f"seed {seed} unreachable for now: {e}")
        self.sync_from_peer(seed)

    # ---------------------------------------------------------------- mining
    def miner_loop(self):
        p = self.node.p
        log(f"mining to {self.miner[:12]}...")
        while not self.stop.is_set():
            if not self.mining:
                time.sleep(0.5)
                continue
            with self.lock:
                tip = self.node.tip
                height = tip.height + 1
                diff = self.node.next_difficulty()
                block = Block(
                    height, tip.hash(), max(int(time.time()), tip.timestamp),
                    self.miner, block_reward(height, self.node.supply, p),
                    list(self.node.mempool))
            found = False
            while not self.stop.is_set():
                for _ in range(2000):
                    if meets_difficulty(block.hash(), diff):
                        found = True
                        break
                    block.nonce += 1
                if found:
                    break
                if not self.mining:
                    break
                with self.lock:
                    if self.node.tip.hash() != block.prev_hash:
                        break  # someone else found a block; restart on new tip
            if not found or not self.mining:
                continue
            with self.lock:
                if self.node.tip.hash() != block.prev_hash:
                    continue
                try:
                    self.node.add_block(block)
                except InvalidBlock as e:
                    log("own block rejected:", e)
                    continue
                self.known.add(block.hash())
                self._save_block(block)
            log(f"MINED block {block.height} ({block.hash()[:10]}), "
                f"{len(block.txs)} tx")
            self.broadcast("/block", {"block": block_to_dict(block),
                                      "from": self.url})

    # ----------------------------------------------------------------- views
    def status(self) -> dict:
        with self.lock:
            p, chain = self.node.p, self.node.chain
            height = chain[-1].height
            span = min(10, height - 1)
            avg = ((chain[-1].timestamp - chain[-1 - span].timestamp) / span
                   if span >= 1 else None)
            return {"url": self.url, "height": height,
                    "tip": chain[-1].hash(), "work": self.node.total_work(),
                    "supply": self.node.supply, "peers": len(self.peers),
                    "mempool": len(self.node.mempool),
                    "difficulty": self.node.next_difficulty(),
                    "avg_block_time": avg,
                    "blocks_to_retarget": p.retarget_interval
                    - height % p.retarget_interval,
                    "bits": p.difficulty_bits, "block_time": p.target_block_time,
                    "retarget": p.retarget_interval, "rules": self.rules(),
                    "miner": self.miner,
                    "mining": bool(self.mining and self.miner is not None)}

    def account(self, addr: str) -> dict:
        with self.lock:
            pending = sum(1 for t in self.node.mempool if t.sender == addr)
            nonce = self.node.nonces.get(addr, 0)
            return {"address": addr, "balance": self.node.balances.get(addr, 0),
                    "nonce": nonce, "next_nonce": nonce + pending}


def make_handler(nn: NetNode):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code: int, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json_body(self):
            n = int(self.headers.get("Content-Length", 0))
            if n > MAX_BODY or (self.path.startswith("/vault/") and n > 8192):
                raise ValueError("body too large")
            return json.loads(self.rfile.read(n) or b"{}")

        def do_GET(self):
            path = urlparse(self.path).path.rstrip("/")
            if path == "/status":
                return self._send(200, nn.status())
            if path == "/peers":
                with nn.lock:
                    return self._send(200, {"peers": sorted(nn.peers)})
            if path == "/chain":
                with nn.lock:
                    return self._send(200, [block_to_dict(b) for b in nn.node.chain[1:]])
            if path.startswith("/account/"):
                return self._send(200, nn.account(path.split("/", 2)[2]))
            if path.startswith("/vault/"):
                if not nn._vault_rate_ok(self.client_address[0]):
                    return self._send(429, {"error": "slow down"})
                try:
                    blob = nn.vault_get(path.split("/", 2)[2])
                except ValueError:
                    return self._send(400, {"error": "bad id"})
                if blob is None:
                    return self._send(404, {"error": "not found"})
                return self._send(200, {"blob": blob})
            self._send(404, {"error": "not found"})

        def do_POST(self):
            path = urlparse(self.path).path.rstrip("/")
            try:
                body = self._json_body()
                if path == "/block":
                    r = nn.receive_block(body["block"], body.get("from"))
                    return self._send(200, {"result": r})
                if path == "/tx":
                    return self._send(200, {"result": nn.receive_tx(body)})
                if path == "/miner":
                    # Only the wallet on this same device may change where rewards go.
                    if (self.client_address[0] not in ("127.0.0.1", "::1")
                            or self.headers.get("X-Sthir-UI") != "1"):
                        return self._send(403, {"error": "forbidden"})
                    return self._send(200, {"miner": nn.set_miner(body.get("address"))})
                if path == "/mining":
                    if (self.client_address[0] not in ("127.0.0.1", "::1")
                            or self.headers.get("X-Sthir-UI") != "1"):
                        return self._send(403, {"error": "forbidden"})
                    return self._send(200, {"mining": nn.set_mining(body.get("on"))})
                if path == "/peer":
                    return self._send(200, {"added": nn.add_peer(body.get("url"))})
                if path.startswith("/vault/"):
                    if not nn._vault_rate_ok(self.client_address[0]):
                        return self._send(429, {"error": "slow down"})
                    nn.vault_put(path.split("/", 2)[2], body.get("blob"))
                    return self._send(200, {"saved": True})
                self._send(404, {"error": "not found"})
            except (InvalidBlock, KeyError, ValueError, TypeError) as e:
                self._send(400, {"error": f"{type(e).__name__}: {e}"})

    return Handler


# ----------------------------------------------------------------- commands
def cmd_node(a):
    miner = resolve_address(a.mine) if a.mine else None
    advertise = a.advertise or f"http://127.0.0.1:{a.port}"
    if a.block_time < 1 or a.retarget < 3:
        raise SystemExit("--block-time must be >= 1 and --retarget must be >= 3")
    params = Params(blocks_per_year=31_536_000 // a.block_time,
                    difficulty_bits=a.bits, target_block_time=a.block_time,
                    retarget_interval=a.retarget)
    nn = NetNode(params, advertise, miner)
    nn.mine_later = bool(a.mine_later) and miner is None
    if a.no_save:
        log("chain is NOT saved (--no-save): it is lost when this node stops")
    else:
        data_dir = a.data or os.path.join("sthir-data", str(a.port))
        nn.store = ChainStore(data_dir, nn.rules())
        nn.vault_dir = os.path.join(data_dir, "vaults")
        nn.pause_file = os.path.join(data_dir, "mining.off")
        nn.mining = not os.path.exists(nn.pause_file)   # remember an "off" across restarts
        nn.load_saved()
    server = ThreadingHTTPServer((a.host, a.port), make_handler(nn))
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log(f"node listening on {a.host}:{a.port}, advertising {nn.url}; rules: "
        f"start {a.bits} bits, {a.block_time}s blocks, retarget every {a.retarget}")
    for seed in a.peer or []:
        nn.connect_seed(seed)
    threading.Thread(target=nn.poll_loop, daemon=True).start()
    if miner:
        threading.Thread(target=nn.miner_loop, daemon=True).start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        nn.stop.set()
        log("bye")


def cmd_wallet(a):
    if a.action == "new":
        w = new_wallet(a.file)
        print(f"saved private key to {a.file} (keep it secret, back it up)")
    else:
        w = load_wallet(a.file)
    print("address:", w.address)


def cmd_send(a):
    w = load_wallet(a.key)
    acct = http_get(f"{a.node}/account/{w.address}")
    tx = Tx.create(w, resolve_address(a.to), int(Decimal(a.amount) * UNIT),
                   int(Decimal(a.fee) * UNIT), acct["next_nonce"])
    try:
        print(http_post(f"{a.node}/tx", tx_to_dict(tx)))
    except urllib.error.HTTPError as e:
        print("rejected:", e.read().decode())


def cmd_balance(a):
    addr = resolve_address(a.who)
    acct = http_get(f"{a.node}/account/{addr}")
    print(f"{acct['balance'] / UNIT:.8f} coins (next nonce {acct['next_nonce']})")


def cmd_status(a):
    st = http_get(f"{a.node}/status")
    st["supply"] = f"{st['supply'] / UNIT:.2f} coins"
    st["tip"] = st["tip"][:16]
    print(json.dumps(st, indent=2))


def _wait(cond, timeout=90, step=0.5):
    end = time.time() + timeout
    while time.time() < end:
        try:
            if cond():
                return True
        except Exception:
            pass
        time.sleep(step)
    return False


def cmd_demo(_a):
    tmp = tempfile.mkdtemp(prefix="sthir_demo_")
    alice = new_wallet(os.path.join(tmp, "alice.key"))
    bob = new_wallet(os.path.join(tmp, "bob.key"))
    me = os.path.abspath(__file__)
    ports = {"A": 5001, "B": 5002, "C": 5003}
    urls = {k: f"http://127.0.0.1:{p}" for k, p in ports.items()}
    procs = []

    def start(name, *extra):
        procs.append(subprocess.Popen(
            [sys.executable, me, "node", "--port", str(ports[name]),
             "--bits", "10", "--block-time", "2", "--retarget", "8",
             "--no-save", *extra],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))

    def height(n):
        return http_get(urls[n] + "/status")["height"]

    def bal(n):
        return http_get(f"{urls[n]}/account/{bob.address}")["balance"]

    try:
        print("Starting 3 nodes: A (miner), B (peers with A), C (peers with B only)")
        start("A", "--mine", alice.address)
        start("B", "--peer", urls["A"])
        start("C", "--peer", urls["B"])
        if not _wait(lambda: all(height(n) >= 0 for n in "ABC"), 20):
            raise SystemExit("nodes did not start")
        if not _wait(lambda: all(height(n) >= 3 for n in "ABC"), 90):
            raise SystemExit("nodes did not converge on height >= 3")
        print("heights after mining:", {n: height(n) for n in "ABC"})

        key = os.path.join(tmp, "alice.key")
        print("Alice sends 0.5 coins to Bob, submitted to node C (not the miner)")
        cmd_send(argparse.Namespace(node=urls["C"], key=key, to=bob.address,
                                    amount="0.5", fee="0.001"))
        want = UNIT // 2
        pay_ok = _wait(lambda: all(bal(n) == want for n in "ABC"), 90)
        print("Bob's balance as seen by each node:",
              {n: bal(n) / UNIT for n in "ABC"})

        status = lambda n: http_get(urls[n] + "/status")
        d0 = 1 << status("A")["bits"]  # the starting difficulty
        print(f"Difficulty starts at {d0:,}. Target block time is 2 s, "
              "so blocks are far too fast at first.")
        raised = _wait(lambda: all(status(n)["difficulty"] >= 16 * d0
                                   for n in "ABC"), 120)
        print("difficulty on each node:",
              {n: f"{status(n)['difficulty']:,}" for n in "ABC"})
        _wait(lambda: (status("A")["avg_block_time"] or 0) >= 1.0, 150)
        h0 = height("A")
        _wait(lambda: height("A") >= h0 + 16, 150)
        recent = http_get(urls["A"] + "/chain")[-17:]
        avg = (recent[-1]["timestamp"] - recent[0]["timestamp"]) / (len(recent) - 1)
        settled = 0.5 <= avg <= 8
        print(f"average block time over the last 16 blocks: {avg:.1f} s "
              "(target 2 s)")
        print("heights:", {n: height(n) for n in "ABC"})
        ok = pay_ok and raised and settled
        print("RESULT:", "PASS" if ok else "FAIL")
        return 0 if ok else 1
    finally:
        for p in procs:
            p.terminate()
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(prog="sthir_net")
    sub = ap.add_subparsers(dest="cmd", required=True)

    w = sub.add_parser("wallet", help="create or show a wallet key file")
    w.add_argument("action", choices=["new", "show"])
    w.add_argument("--file", default="wallet.key")
    w.set_defaults(fn=cmd_wallet)

    n = sub.add_parser("node", help="run a node")
    n.add_argument("--host", default="0.0.0.0")
    n.add_argument("--port", type=int, default=5001)
    n.add_argument("--advertise", help="URL peers should use to reach you "
                   "(default http://127.0.0.1:PORT; use your LAN IP for other devices)")
    n.add_argument("--peer", action="append", help="seed peer URL (repeatable)")
    n.add_argument("--mine", help="wallet key file or 64-hex address to mine to")
    n.add_argument("--mine-later", action="store_true",
                   help="start without a miner address; the wallet app on this device sets it at login")
    n.add_argument("--bits", type=int, default=16,
                   help="starting difficulty (2^bits hashes per block)")
    n.add_argument("--block-time", type=int, default=300,
                   help="target seconds per block")
    n.add_argument("--retarget", type=int, default=144,
                   help="blocks between difficulty adjustments "
                   "(all nodes must use the same --bits, --block-time, --retarget)")
    n.add_argument("--data", help="folder where the chain is saved "
                   "(default sthir-data/<port>)")
    n.add_argument("--no-save", action="store_true",
                   help="keep the chain in memory only")
    n.set_defaults(fn=cmd_node)

    s = sub.add_parser("send", help="send coins")
    s.add_argument("--node", required=True)
    s.add_argument("--key", default="wallet.key")
    s.add_argument("--to", required=True, help="key file or address")
    s.add_argument("--amount", required=True)
    s.add_argument("--fee", default="0.001")
    s.set_defaults(fn=cmd_send)

    b = sub.add_parser("balance", help="show a balance")
    b.add_argument("--node", required=True)
    b.add_argument("who", help="key file or address")
    b.set_defaults(fn=cmd_balance)

    st = sub.add_parser("status", help="show node status")
    st.add_argument("--node", required=True)
    st.set_defaults(fn=cmd_status)

    d = sub.add_parser("demo", help="run a 3-node local network and a payment")
    d.set_defaults(fn=cmd_demo)

    a = ap.parse_args()
    sys.exit(a.fn(a) or 0)


if __name__ == "__main__":
    main()
