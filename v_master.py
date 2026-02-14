import hashlib, json, time, os, threading, shutil
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# --- CONFIG VEXON FAST-MINING ---
DB_FILE = "vexon_ledger.json"
TARGET_BLOCK_TIME = 60          
DECIMALS = 10**18
MINER_ADDR = "vxq_mobile_timelord_sovereign"

class VexonChain:
    def __init__(self):
        self.chain = []
        self.state = {} 
        self.lock = threading.Lock()
        self.load_node()
        # Jalankan mesin mining otomatis
        threading.Thread(target=self.mine_pot, daemon=True).start()

    def load_node(self):
        if not os.path.exists(DB_FILE):
            self.genesis()
            return
        with open(DB_FILE, 'r') as f:
            self.chain = json.load(f)
        for b in self.chain: self.sync_state(b)
        print(f"[*] NODE AKTIF! Target: {TARGET_BLOCK_TIME}s/Blok")

    def sync_state(self, block):
        for tx in block["transactions"]:
            r, a = tx.get("to"), int(tx.get("amount", 0))
            if r: self.state[r.lower()] = self.state.get(r.lower(), 0) + a

    def mine_pot(self):
        while True:
            now = int(time.time())
            elapsed = now - self.chain[-1]['timestamp']
            if elapsed >= TARGET_BLOCK_TIME:
                with self.lock:
                    reward = {"from": None, "to": MINER_ADDR.lower(), "amount": 50*DECIMALS, "type": "REWARD"}
                    new_b = {
                        "index": len(self.chain),
                        "timestamp": now,
                        "transactions": [reward],
                        "previous_hash": self.chain[-1]['hash']
                    }
                    new_b["hash"] = hashlib.sha256(json.dumps(new_b, sort_keys=True).encode()).hexdigest()
                    self.chain.append(new_b)
                    self.sync_state(new_b)
                    with open(DB_FILE, 'w') as f: json.dump(self.chain, f)
                    print(f"[+] BLOCK #{new_b['index']} MINED! Saldo: {self.state.get(MINER_ADDR.lower(),0)/DECIMALS} VXN")
            time.sleep(5)

    def genesis(self):
        b = {"index": 0, "timestamp": int(time.time()), "transactions": [], "previous_hash": "0", "hash": "genesis_hash"}
        self.chain = [b]
        with open(DB_FILE, 'w') as f: json.dump(self.chain, f)

vxn = VexonChain()

@app.route('/rpc', methods=['POST'])
def rpc():
    return jsonify({"blocks": len(vxn.chain), "balance": vxn.state.get(MINER_ADDR.lower(), 0)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8545)
