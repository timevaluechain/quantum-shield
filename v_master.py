import hashlib, json, time, os, threading, shutil, requests, socket
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# --- CONFIG VEXON ---
DB_FILE = "vexon_ledger.json"
TARGET_BLOCK_TIME = 60          
DECIMALS = 10**18
MINER_ADDR = "vxq_mobile_timelord_sovereign"
PORT = 8545

class VexonChain:
    def __init__(self):
        self.chain = []
        self.state = {} 
        self.mempool = []
        self.peers = set() # Kosongkan, nanti keisi otomatis lewat discovery
        self.lock = threading.Lock()
        self.load_node()
        
        # --- MESIN UTAMA ---
        threading.Thread(target=self.mine_pot, daemon=True).start()
        threading.Thread(target=self.auto_discovery, daemon=True).start()
        threading.Thread(target=self.p2p_sync, daemon=True).start()

    def load_node(self):
        if not os.path.exists(DB_FILE):
            self.genesis()
            return
        with open(DB_FILE, 'r') as f: self.chain = json.load(f)
        self.rebuild_state()
        print(f"[*] NODE MEK-EDITION ONLINE!")
        print(f"[*] Alamat Miner: {MINER_ADDR}")

    def get_bal(self, addr):
        return self.state.get(addr.lower(), 0) / DECIMALS

    def rebuild_state(self):
        self.state = {}
        for b in self.chain:
            for tx in b["transactions"]:
                s, r, a = tx.get("from"), tx.get("to"), int(tx.get("amount", 0))
                if s: self.state[s.lower()] = self.state.get(s.lower(), 0) - a
                if r: self.state[r.lower()] = self.state.get(r.lower(), 0) + a

    def auto_discovery(self):
        """Nyari temen di Wi-Fi otomatis biar gak perlu server luar"""
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                my_ip = s.getsockname()[0]
                s.close()
                prefix = ".".join(my_ip.split(".")[:-1]) + "."
                for i in range(1, 255):
                    target = f"http://{prefix}{i}:{PORT}"
                    if f"{my_ip}:{PORT}" in target: continue
                    threading.Thread(target=self.ping_peer, args=(target,), daemon=True).start()
            except: pass
            time.sleep(300)

    def ping_peer(self, url):
        try:
            if requests.get(f"{url}/rpc/status", timeout=1).status_code == 200:
                self.peers.add(url)
                print(f"[+] Peer ditemukan: {url}")
        except: pass

    def mine_pot(self):
        while True:
            now = int(time.time())
            if now - self.chain[-1]['timestamp'] >= TARGET_BLOCK_TIME:
                with self.lock:
                    txs = self.mempool[:10]
                    self.mempool = self.mempool[10:]
                    reward = {"from": None, "to": MINER_ADDR.lower(), "amount": 50*DECIMALS, "type": "REWARD"}
                    txs.append(reward)
                    new_b = {
                        "index": len(self.chain),
                        "timestamp": now,
                        "transactions": txs,
                        "previous_hash": self.chain[-1]['hash']
                    }
                    new_b["hash"] = hashlib.sha256(json.dumps(new_b, sort_keys=True).encode()).hexdigest()
                    self.chain.append(new_b)
                    self.rebuild_state()
                    with open(DB_FILE, 'w') as f: json.dump(self.chain, f)
                    print(f"[+] BLOCK #{new_b['index']} MINED! Saldo: {self.get_bal(MINER_ADDR)} VXN")
                    self.broadcast("/p2p/receive", new_b)
            time.sleep(5)

    def broadcast(self, path, data):
        for peer in list(self.peers):
            threading.Thread(target=lambda: requests.post(f"{peer}{path}", json=data, timeout=3), daemon=True).start()

    def p2p_sync(self):
        while True:
            for peer in list(self.peers):
                try:
                    res = requests.get(f"{peer}/rpc/status", timeout=2)
                    if res.json().get("blocks", 0) > len(self.chain):
                        self.sync_chain(peer)
                except: pass
            time.sleep(20)

    def sync_chain(self, peer):
        try:
            res = requests.get(f"{peer}/p2p/full_chain", timeout=10)
            new_c = res.json()
            if len(new_c) > len(self.chain):
                self.chain = new_c
                self.rebuild_state()
                with open(DB_FILE, 'w') as f: json.dump(self.chain, f)
                print(f"[*] Sinkron Berhasil dari {peer}")
        except: pass

    def genesis(self):
        b = {"index":0,"timestamp":int(time.time()),"transactions":[],"previous_hash":"0","hash":"genesis"}
        self.chain = [b]
        with open(DB_FILE, 'w') as f: json.dump(self.chain, f)

vxn = VexonChain()

# --- ROUTES ---
@app.route('/rpc/status')
def status(): return jsonify({"blocks": len(vxn.chain), "peers": list(vxn.peers), "balance": vxn.get_bal(MINER_ADDR)})

@app.route('/p2p/full_chain')
def full_chain(): return jsonify(vxn.chain)

@app.route('/p2p/receive', methods=['POST'])
def receive_block():
    b = request.get_json()
    if b['index'] == len(vxn.chain) and b['previous_hash'] == vxn.chain[-1]['hash']:
        with vxn.lock:
            vxn.chain.append(b)
            vxn.rebuild_state()
            with open(DB_FILE, 'w') as f: json.dump(vxn.chain, f)
        return "OK"
    return "Rejected", 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT)
