import hashlib, json, time, os, threading, hmac
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# --- CONFIG ---
DB_FILE = "vexon_ledger.json"
DECIMALS = 10**18
MINER_ADDR = "vxq_mobile_quantum_sovereign"
PORT = 8545

class VexonChain:
    def __init__(self):
        self.chain = []
        self.mempool = []
        self.lock = threading.Lock()
        self.load_node()
        # Thread nambang biar jalan terus di background
        threading.Thread(target=self.mine_pot, daemon=True).start()

    def verify_tx_pq(self, tx):
        """Verifikasi darurat pake HMAC biar gak error library"""
        try:
            msg = f"{tx['from']}{tx['to']}{tx['amount']}{tx['nonce']}{tx['timestamp']}".encode()
            expected_sig = hmac.new(tx['pub_key'].encode(), msg, hashlib.sha256).hexdigest()
            return tx['signature'] == expected_sig
        except: return False

    def mine_pot(self):
        while True:
            last_b = self.chain[-1]
            with self.lock:
                # Ambil transaksi dari mempool
                valid_txs = [tx for tx in self.mempool[:10] if self.verify_tx_pq(tx)]
                self.mempool = self.mempool[len(valid_txs):]
                
                # Reward 50 VXN per blok
                valid_txs.append({"from": None, "to": MINER_ADDR, "amount": 50 * DECIMALS, "type": "REWARD"})
                
                diff, nonce = 4, 0
                while True:
                    cand = {"index": len(self.chain), "timestamp": int(time.time()), "transactions": valid_txs, "previous_hash": last_b['hash'], "nonce": nonce}
                    h = hashlib.sha256(json.dumps(cand, sort_keys=True).encode()).hexdigest()
                    if h.startswith('0' * diff):
                        cand["hash"] = h
                        self.chain.append(cand)
                        with open(DB_FILE, 'w') as f: json.dump(self.chain, f)
                        # INI LOG YANG LO CARI SU!
                        print(f"[+] BLOCK #{cand['index']} MINED | Balance: {len(self.chain)*50} VXN")
                        break
                    nonce += 1
                    if nonce % 20000 == 0: time.sleep(0.01)
            time.sleep(1)

    def load_node(self):
        if os.path.exists(DB_FILE):
            try:
                with open(DB_FILE, 'r') as f: self.chain = json.load(f)
            except: self.genesis()
        else: self.genesis()

    def genesis(self):
        gen = {"index": 0, "hash": "0", "timestamp": int(time.time()), "transactions": []}
        self.chain = [gen]

vxn = VexonChain()

@app.route('/rpc/status')
def status(): 
    return jsonify({"height": len(vxn.chain), "total_mined": len(vxn.chain)*50})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT)
