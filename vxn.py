import hashlib, json, time, os, asyncio, secrets, threading, requests, sys
from flask import Flask, jsonify, request

# --- [RFC 8391 CONFIG] ---
W, N = 16, 32
LEN1, LEN2 = 64, 3 
LEN = LEN1 + LEN2
DECIMALS = 10**18
DB_FILE, WALLET_FILE = "vexon_mainnet.json", "wallet_v115.json"
TARGET_BLOCK_TIME = 30
PEERS = set(["127.0.0.1:8546"]) 

class ADRS:
    WOTS_OTS, L_TREE, HASH_TREE = 0, 1, 2
    def __init__(self):
        self.layer = self.tree_address = self.type = self.ots_address = 0
        self.chain_address = self.hash_address = self.key_and_mask = 0
    def serialize(self):
        return (self.layer.to_bytes(4,'big') + self.tree_address.to_bytes(8,'big') +
                self.type.to_bytes(4,'big') + self.ots_address.to_bytes(4,'big') +
                self.chain_address.to_bytes(4,'big') + self.hash_address.to_bytes(4,'big') +
                self.key_and_mask.to_bytes(4,'big'))

class VexonInvincible:
    def __init__(self):
        self.chain, self.balances, self.used_indices = [], {}, {}
        self.mempool = [] # ✅ New: Mempool untuk transaksi user
        self._init_wallet()
        self.load_all()

    # --- [XMSS CORE & SIGNING] ---
    def _get_checksum(self, msg_indices):
        csum = sum(W - 1 - i for i in msg_indices)
        csum <<= 4
        res = []
        for _ in range(LEN2):
            res.append(csum & 0x0F); csum >>= 4
        return res[::-1]

    def _hash_f(self, p_seed, adrs, m):
        adrs.key_and_mask = 0
        k = hashlib.sha256(p_seed + adrs.serialize()).digest()
        adrs.key_and_mask = 1
        bm = hashlib.sha256(p_seed + adrs.serialize()).digest()
        return hashlib.sha256(k + bytes(a ^ b for a, b in zip(m, bm))).digest()

    def _l_tree(self, p_seed, adrs, pks):
        adrs.type = ADRS.L_TREE
        while len(pks) > 1:
            new_pks = []
            for i in range(0, len(pks) // 2):
                adrs.tree_address = i
                new_pks.append(hashlib.sha256(p_seed + adrs.serialize() + pks[2*i] + pks[2*i+1]).digest())
            if len(pks) % 2: new_pks.append(pks[-1])
            pks = new_pks; adrs.layer += 1
        return pks[0]

    def xmss_sign(self, msg_h):
        priv_seed = hashlib.sha256(self.sk_seed + self.ots_index.to_bytes(4,'big')).digest()
        adrs = ADRS(); adrs.ots_address = self.ots_index
        indices = []
        for b in msg_h: indices.extend([b >> 4, b & 0x0F])
        indices += self._get_checksum(indices)
        sig = []
        for i in range(LEN):
            adrs.chain_address, curr = i, hashlib.sha256(priv_seed + i.to_bytes(4,'big')).digest()
            for j in range(indices[i]):
                adrs.hash_address = j
                curr = self._hash_f(self.pub_seed, adrs, curr)
            sig.append(curr.hex())
        return sig

    def verify_xmss_sig(self, tx):
        try:
            msg_h = bytes.fromhex(tx['hash'])
            sig, p_seed = [bytes.fromhex(s) for s in tx['sig']], bytes.fromhex(tx['pub_seed'])
            indices = []
            for b in msg_h: indices.extend([b >> 4, b & 0x0F])
            indices += self._get_checksum(indices)
            adrs = ADRS(); adrs.ots_address = tx['idx']
            pks = []
            for i in range(LEN):
                adrs.chain_address, curr = i, sig[i]
                for j in range(indices[i], W - 1):
                    adrs.hash_address = j
                    curr = self._hash_f(p_seed, adrs, curr)
                pks.append(curr)
            root = self._l_tree(p_seed, adrs, pks)
            return tx['from'] == f"vxq_{root.hex()[:12]}"
        except: return False

    # --- [CONSENSUS & RE-ORG] ---
    def calculate_work(self, chain):
        return sum(2**b.get('diff', 4) for b in chain)

    def validate_block(self, block, prev_block):
        if block['prev'] != prev_block['hash']: return False
        content = {k: v for k, v in block.items() if k != 'hash'}
        if hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest() != block['hash']: return False
        if not block['hash'].startswith("0" * block['diff']): return False
        for tx in block['txs']:
            if not self.verify_xmss_sig(tx): return False
        return True

    # ✅ [FIX: apply_block sekarang tahan error]
    def apply_block(self, block):
        if 'txs' not in block: return
        for tx in block['txs']:
            s = tx.get('from')
            idx = tx.get('idx')
            amt = tx.get('amount', 0)
            if not s or idx is None: continue # Skip if data is malformed
            
            self.used_indices.setdefault(s, set()).add(idx)
            # Logic: Sender berkurang, Receiver bertambah (simple model)
            if tx.get('type') == 'reward':
                self.balances[s] = self.balances.get(s, 0) + amt
            else:
                # Normal TX (Simplified)
                receiver = tx.get('to')
                self.balances[s] = self.balances.get(s, 0) - amt
                if receiver: self.balances[receiver] = self.balances.get(receiver, 0) + amt

    # --- [MINING & P2P] ---
    async def mining_engine(self):
        print(f"\033[94m[VEXON] Mining Active: {self.addr}\033[0m")
        while True:
            diff = self.get_difficulty()
            reward = (50 * DECIMALS) >> (len(self.chain) // 210000)
            
            # Coinbase TX
            cb_tx = {"from": self.addr, "amount": reward, "idx": self.ots_index, "type": "reward", "pub_seed": self.pub_seed.hex()}
            cb_tx['hash'] = hashlib.sha256(json.dumps(cb_tx, sort_keys=True).encode()).hexdigest()
            cb_tx['sig'] = self.xmss_sign(bytes.fromhex(cb_tx['hash']))
            
            # Ambil dari mempool (Max 10 tx)
            current_txs = [cb_tx] + self.mempool[:10]
            
            block = {"idx": len(self.chain), "prev": self.chain[-1]['hash'], "txs": current_txs, "ts": int(time.time()), "diff": diff, "nonce": 0}
            
            while True:
                h = hashlib.sha256(json.dumps(block, sort_keys=True).encode()).hexdigest()
                if h.startswith("0" * diff):
                    block['hash'] = h; break
                block['nonce'] += 1
                if block['nonce'] % 10000 == 0: await asyncio.sleep(0.001)
            
            if self.validate_block(block, self.chain[-1]):
                self.chain.append(block); self.apply_block(block)
                self.ots_index += 1; self.mempool = self.mempool[10:] # Clear mempool
                self._save_all(); print(f"\r\033[92m[MINED] #{len(self.chain)-1} | Diff: {diff}\033[0m", end="")
                threading.Thread(target=lambda: self.broadcast_block(block)).start()

    def get_difficulty(self):
        if len(self.chain) < 10: return 4
        avg = sum(self.chain[i]['ts'] - self.chain[i-1]['ts'] for i in range(-9, 0)) / 9
        last_diff = self.chain[-1].get('diff', 4)
        return last_diff + 1 if avg < TARGET_BLOCK_TIME * 0.7 else max(1, last_diff - 1) if avg > TARGET_BLOCK_TIME * 1.3 else last_diff

    def broadcast_block(self, block):
        for p in list(PEERS):
            try: requests.post(f"http://{p}/receive_block", json=block, timeout=1)
            except: pass

    # --- [BOOTSTRAP & DISK] ---
    def _init_wallet(self):
        if os.path.exists(WALLET_FILE):
            w = json.load(open(WALLET_FILE))
            self.sk_seed, self.pub_seed, self.ots_index = bytes.fromhex(w['sk']), bytes.fromhex(w['pk']), w['idx']
        else:
            self.sk_seed, self.pub_seed, self.ots_index = secrets.token_bytes(N), secrets.token_bytes(N), 0
            json.dump({'sk':self.sk_seed.hex(), 'pk':self.pub_seed.hex(), 'idx':0}, open(WALLET_FILE, 'w'))
        self.addr = f"vxq_{hashlib.sha256(self.pub_seed).hexdigest()[:12]}"

    def _save_all(self):
        json.dump({'sk':self.sk_seed.hex(), 'pk':self.pub_seed.hex(), 'idx':self.ots_index}, open(WALLET_FILE, 'w'))
        json.dump(self.chain, open(DB_FILE, 'w'))

    def load_all(self):
        if os.path.exists(DB_FILE): self.chain = json.load(open(DB_FILE))
        else: self.chain = [{"idx":0, "hash":"00000genesis", "ts":int(time.time()), "txs":[], "diff":4, "prev": "0"}]
        self.rebuild_state()

    def rebuild_state(self):
        self.balances, self.used_indices = {}, {}
        for b in self.chain: self.apply_block(b)

# --- [API] ---
vxn = VexonInvincible()
app = Flask(__name__)

@app.route('/get_chain')
def get_chain(): return jsonify(vxn.chain)

@app.route('/balance/<address>')
def get_balance(address): return jsonify({"address": address, "balance": vxn.balances.get(address, 0) / DECIMALS})

@app.route('/receive_block', methods=['POST'])
def receive():
    b = request.json
    if vxn.validate_block(b, vxn.chain[-1]):
        vxn.chain.append(b); vxn.apply_block(b); vxn._save_all()
        return "OK", 200
    return "FAIL", 400

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8545
    threading.Thread(target=lambda: app.run(host='0.0.0.0', port=port), daemon=True).start()
    asyncio.run(vxn.mining_engine())
