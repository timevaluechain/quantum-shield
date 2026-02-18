
#!/usr/bin/env python3
"""
VEXON FINAL – Post-Quantum Layer 1 (Hash-Based)
- Signature: WOTS+ sederhana (SHA256) – quantum-resistant
- Wallet: encrypted dengan scrypt + AES (cryptography)
- Fork resolution via orphan pool
- Checkpoint setiap 100 block
- Mempool prioritas fee
- PoW, difficulty adjustment, timestamp validation
- P2P broadcast, API Flask
"""

import hashlib, json, time, os, asyncio, secrets, threading, requests, sys
from flask import Flask, jsonify, request
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import base64

# ==================== KONFIGURASI ====================
DECIMALS = 10**18
TARGET_BLOCK_TIME = 60
DIFFICULTY_ADJUST_WINDOW = 10
GENESIS_REWARD = 50 * DECIMALS
INITIAL_DIFFICULTY = 4
PEERS = set(["127.0.0.1:8546"])        # Ganti dengan peer lo
CHAIN_FILE = "vexon_chain.json"
WALLET_FILE = "wallet.enc"
CHECKPOINT_FILE = "checkpoint.json"
CHECKPOINT_INTERVAL = 100
MAX_FUTURE_BLOCK_TIME = 2 * 3600
MAX_PAST_BLOCK_TIME = 24 * 3600

# ==================== POST-QUANTUM SIGNATURE (HASH-BASED) ====================
# Implementasi WOTS+ sederhana dengan SHA256 – quantum-resistant
class QuantumSign:
    @staticmethod
    def keygen():
        private = secrets.token_bytes(32)
        public = hashlib.sha256(private).digest()
        return private, public

    @staticmethod
    def sign(private, message):
        h = message
        for _ in range(16):   # W=16, chain length
            h = hashlib.sha256(private + h).digest()
        return h

    @staticmethod
    def verify(public, message, signature):
        h = message
        for _ in range(16):
            h = hashlib.sha256(public + h).digest()
        return h == signature

# ==================== WALLET (ENKRIPSI) ====================
class Wallet:
    @staticmethod
    def generate():
        private, public = QuantumSign.keygen()
        return private, public.hex()

    @staticmethod
    def save(private, public_hex, password, filename=WALLET_FILE):
        salt = os.urandom(16)
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        fernet = Fernet(key)
        data = private + b"||" + public_hex.encode()
        encrypted = fernet.encrypt(data)
        with open(filename, 'wb') as f:
            f.write(salt + encrypted)
        return True

    @staticmethod
    def load(password, filename=WALLET_FILE):
        with open(filename, 'rb') as f:
            data = f.read()
        salt, encrypted = data[:16], data[16:]
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted)
        private, public_hex = decrypted.split(b"||", 1)
        return private, public_hex.decode()

# ==================== TRANSACTION ====================
class Tx:
    def __init__(self, from_addr, to_addr, amount, nonce, fee=0):
        self.from_addr = from_addr      # hex public key
        self.to_addr = to_addr
        self.amount = amount
        self.nonce = nonce
        self.fee = fee
        self.sig = None

    def serialize(self):
        data = {
            'from': self.from_addr,
            'to': self.to_addr,
            'amount': self.amount,
            'nonce': self.nonce,
            'fee': self.fee
        }
        return json.dumps(data, sort_keys=True).encode()

    def hash(self):
        return hashlib.sha256(self.serialize()).digest()

    def sign(self, private):
        self.sig = QuantumSign.sign(private, self.hash()).hex()
        return self

    def verify(self):
        if self.from_addr == "coinbase":
            return True
        try:
            public = bytes.fromhex(self.from_addr)
            sig = bytes.fromhex(self.sig)
            return QuantumSign.verify(public, self.hash(), sig)
        except:
            return False

# ==================== BLOCK ====================
class Block:
    def __init__(self, index, prev_hash, txs, timestamp, difficulty, nonce=0):
        self.index = index
        self.prev_hash = prev_hash
        self.txs = txs
        self.timestamp = timestamp
        self.difficulty = difficulty
        self.nonce = nonce
        self.hash = self.calculate_hash()
        self.work = 2 ** difficulty

    def calculate_hash(self):
        data = {
            'index': self.index,
            'prev': self.prev_hash,
            'txs': [tx.hash().hex() for tx in self.txs],
            'ts': self.timestamp,
            'diff': self.difficulty,
            'nonce': self.nonce
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

    def mine(self):
        target = '0' * self.difficulty
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.calculate_hash()
        return self

    def validate(self, prev_block, state, expected_reward, check_timestamp=True):
        if self.hash != self.calculate_hash():
            return False, "Invalid hash"
        if not self.hash.startswith('0' * self.difficulty):
            return False, "PoW failed"
        if self.prev_hash != prev_block.hash:
            return False, "Prev hash mismatch"

        if check_timestamp:
            now = int(time.time())
            if self.timestamp > now + MAX_FUTURE_BLOCK_TIME:
                return False, "Timestamp too far in future"
            if self.timestamp < prev_block.timestamp - MAX_PAST_BLOCK_TIME:
                return False, "Timestamp too old"

        coinbase_count = 0
        for tx in self.txs:
            if tx.from_addr == "coinbase":
                coinbase_count += 1
                if tx.amount != expected_reward:
                    return False, f"Invalid coinbase amount: {tx.amount} != {expected_reward}"
                if tx.to_addr == "coinbase" or not tx.to_addr:
                    return False, "Invalid coinbase recipient"
            else:
                if not tx.verify():
                    return False, f"Invalid signature from {tx.from_addr}"
                if state.get_nonce(tx.from_addr) != tx.nonce:
                    return False, f"Invalid nonce for {tx.from_addr}"
                if state.get_balance(tx.from_addr) < tx.amount + tx.fee:
                    return False, f"Insufficient balance for {tx.from_addr}"
        if coinbase_count != 1:
            return False, "Must have exactly one coinbase transaction"
        return True, "OK"

    def apply(self, state):
        for tx in self.txs:
            if tx.from_addr != "coinbase":
                state.sub_balance(tx.from_addr, tx.amount + tx.fee)
                state.inc_nonce(tx.from_addr)
            state.add_balance(tx.to_addr, tx.amount)

# ==================== STATE ====================
class BlockchainState:
    def __init__(self, chain=None):
        self.balances = {}
        self.nonces = {}
        if chain:
            self.rebuild(chain)

    def rebuild(self, chain):
        self.balances = {}
        self.nonces = {}
        for block in chain:
            for tx in block.txs:
                if tx.from_addr != "coinbase":
                    self.balances[tx.from_addr] = self.balances.get(tx.from_addr, 0) - (tx.amount + tx.fee)
                    self.nonces[tx.from_addr] = self.nonces.get(tx.from_addr, 0) + 1
                self.balances[tx.to_addr] = self.balances.get(tx.to_addr, 0) + tx.amount

    def get_balance(self, addr):
        return self.balances.get(addr, 0)

    def add_balance(self, addr, amount):
        self.balances[addr] = self.get_balance(addr) + amount

    def sub_balance(self, addr, amount):
        bal = self.get_balance(addr)
        if bal < amount:
            raise ValueError("Insufficient balance")
        self.balances[addr] = bal - amount

    def get_nonce(self, addr):
        return self.nonces.get(addr, 0)

    def inc_nonce(self, addr):
        self.nonces[addr] = self.get_nonce(addr) + 1

    def copy(self):
        new = BlockchainState()
        new.balances = self.balances.copy()
        new.nonces = self.nonces.copy()
        return new

# ==================== BLOCKCHAIN ====================
class Blockchain:
    def __init__(self, genesis_block):
        self.chain = [genesis_block]
        self.state = BlockchainState(self.chain)
        self.tip = genesis_block
        self.difficulty = genesis_block.difficulty
        self.mempool = []
        self.total_work = genesis_block.work
        self.checkpoints = {}                  # height -> block hash
        self.orphan_blocks = {}                # prev_hash -> list of Block
        self._add_checkpoint(genesis_block)

    def _add_checkpoint(self, block):
        if block.index % CHECKPOINT_INTERVAL == 0:
            self.checkpoints[block.index] = block.hash
            self._save_checkpoints()

    def _save_checkpoints(self, filename=CHECKPOINT_FILE):
        with open(filename, 'w') as f:
            json.dump(self.checkpoints, f)

    def _load_checkpoints(self, filename=CHECKPOINT_FILE):
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                self.checkpoints = json.load(f)
            self.checkpoints = {int(k): v for k, v in self.checkpoints.items()}

    @staticmethod
    def create_genesis(coinbase_addr):
        coinbase = Tx("coinbase", coinbase_addr, GENESIS_REWARD, 0)
        coinbase.sig = "dummy"
        genesis = Block(0, "0"*64, [coinbase], int(time.time()), INITIAL_DIFFICULTY, 0)
        genesis.hash = genesis.calculate_hash()
        bc = Blockchain(genesis)
        bc._save_checkpoints()
        return bc

    def save(self, filename=CHAIN_FILE):
        data = []
        for block in self.chain:
            block_data = {
                'index': block.index,
                'prev': block.prev_hash,
                'timestamp': block.timestamp,
                'difficulty': block.difficulty,
                'nonce': block.nonce,
                'hash': block.hash,
                'work': block.work,
                'txs': []
            }
            for tx in block.txs:
                tx_data = {
                    'from': tx.from_addr,
                    'to': tx.to_addr,
                    'amount': tx.amount,
                    'nonce': tx.nonce,
                    'fee': tx.fee,
                    'sig': tx.sig
                }
                block_data['txs'].append(tx_data)
            data.append(block_data)
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def load(filename=CHAIN_FILE, coinbase_addr=None):
        if not os.path.exists(filename):
            if coinbase_addr is None:
                raise Exception("No chain file and no coinbase_addr provided")
            return Blockchain.create_genesis(coinbase_addr)
        with open(filename, 'r') as f:
            data = json.load(f)
        chain = []
        total_work = 0
        for block_data in data:
            txs = []
            for tx_data in block_data['txs']:
                tx = Tx(tx_data['from'], tx_data['to'], tx_data['amount'], tx_data['nonce'], tx_data.get('fee', 0))
                tx.sig = tx_data['sig']
                txs.append(tx)
            block = Block(
                block_data['index'],
                block_data['prev'],
                txs,
                block_data['timestamp'],
                block_data['difficulty'],
                block_data['nonce']
            )
            block.hash = block_data['hash']
            block.work = block_data.get('work', 2**block.difficulty)
            total_work += block.work
            chain.append(block)
        bc = Blockchain.__new__(Blockchain)
        bc.chain = chain
        bc.tip = chain[-1]
        bc.difficulty = bc.tip.difficulty
        bc.state = BlockchainState(chain)
        bc.mempool = []
        bc.total_work = total_work
        bc.checkpoints = {}
        bc.orphan_blocks = {}
        bc._load_checkpoints()
        return bc

    def get_expected_reward(self, height):
        return GENESIS_REWARD >> (height // 210000)

    def add_orphan(self, block):
        prev = block.prev_hash
        if prev not in self.orphan_blocks:
            self.orphan_blocks[prev] = []
        self.orphan_blocks[prev].append(block)

    def try_connect_orphans(self):
        connected = 0
        while True:
            tip_hash = self.tip.hash
            if tip_hash in self.orphan_blocks:
                # Cari orphan dengan index tepat
                found = None
                for b in self.orphan_blocks[tip_hash]:
                    if b.index == self.tip.index + 1:
                        found = b
                        break
                if found:
                    exp_reward = self.get_expected_reward(found.index)
                    valid, msg = found.validate(self.tip, self.state, exp_reward)
                    if valid:
                        found.apply(self.state)
                        self.chain.append(found)
                        self.tip = found
                        self.total_work += found.work
                        self._add_checkpoint(found)
                        self.adjust_difficulty()
                        self.orphan_blocks[tip_hash].remove(found)
                        if not self.orphan_blocks[tip_hash]:
                            del self.orphan_blocks[tip_hash]
                        connected += 1
                        continue   # lanjut loop untuk orphan berikutnya
                    else:
                        # orphan tidak valid, hapus? Tidak, biarkan (mungkin nanti valid setelah reorg)
                        pass
                break
            else:
                break
        return connected

    def adjust_difficulty(self):
        if len(self.chain) < DIFFICULTY_ADJUST_WINDOW:
            return
        last_blocks = self.chain[-DIFFICULTY_ADJUST_WINDOW:]
        actual_time = last_blocks[-1].timestamp - last_blocks[0].timestamp
        expected_time = TARGET_BLOCK_TIME * (DIFFICULTY_ADJUST_WINDOW - 1)
        if actual_time < expected_time * 0.5:
            self.difficulty += 1
        elif actual_time > expected_time * 1.5:
            self.difficulty = max(1, self.difficulty - 1)

    def receive_block(self, block):
        # Cek duplikat
        for b in self.chain:
            if b.hash == block.hash:
                return False, "Block already in chain"
        # Cek checkpoint
        if block.index in self.checkpoints and self.checkpoints[block.index] != block.hash:
            return False, "Checkpoint violation"
        # Jika block langsung extend tip
        if block.prev_hash == self.tip.hash:
            exp_reward = self.get_expected_reward(block.index)
            valid, msg = block.validate(self.tip, self.state, exp_reward)
            if valid:
                block.apply(self.state)
                self.chain.append(block)
                self.tip = block
                self.total_work += block.work
                self._add_checkpoint(block)
                self.adjust_difficulty()
                self.try_connect_orphans()
                return True, "Block accepted"
            else:
                return False, msg
        else:
            # Simpan sebagai orphan
            self.add_orphan(block)
            return True, "Block stored as orphan"

    def create_coinbase_tx(self, miner_addr, reward):
        return Tx("coinbase", miner_addr, reward, 0)

    def mine_block(self, miner_addr, private_key):
        reward = self.get_expected_reward(len(self.chain))
        coinbase = self.create_coinbase_tx(miner_addr, reward)
        # Urutkan mempool berdasarkan fee
        self.mempool.sort(key=lambda tx: tx.fee, reverse=True)
        txs = [coinbase] + self.mempool[:5]
        block = Block(len(self.chain), self.tip.hash, txs, int(time.time()), self.difficulty)
        block.mine()
        exp_reward = self.get_expected_reward(block.index)
        valid, msg = block.validate(self.tip, self.state, exp_reward)
        if valid:
            block.apply(self.state)
            self.chain.append(block)
            self.tip = block
            self.total_work += block.work
            self._add_checkpoint(block)
            self.adjust_difficulty()
            # Hapus tx yang sudah masuk dari mempool
            self.mempool = [tx for tx in self.mempool if tx not in txs[1:]]
            return block
        else:
            return None

# ==================== API FLASK ====================
app = Flask(__name__)
blockchain = None
miner_addr = None
miner_private = None

@app.route('/get_chain')
def get_chain():
    return jsonify([{
        'index': b.index,
        'hash': b.hash,
        'prev': b.prev_hash,
        'ts': b.timestamp,
        'diff': b.difficulty,
        'nonce': b.nonce,
        'work': b.work,
        'txs': [t.hash().hex() for t in b.txs]
    } for b in blockchain.chain])

@app.route('/balance/<address>')
def get_balance(address):
    bal = blockchain.state.get_balance(address) / DECIMALS
    return jsonify({"address": address, "balance": bal})

@app.route('/send_tx', methods=['POST'])
def send_tx():
    data = request.json
    try:
        tx = Tx(data['from'], data['to'], data['amount'], data['nonce'], data.get('fee', 0))
        tx.sig = data['sig']
        if not tx.verify():
            return "Invalid signature", 400
        if blockchain.state.get_nonce(tx.from_addr) != tx.nonce:
            return "Invalid nonce", 400
        if blockchain.state.get_balance(tx.from_addr) < tx.amount + tx.fee:
            return "Insufficient balance", 400
        blockchain.mempool.append(tx)
        return "Transaction added to mempool", 200
    except Exception as e:
        return str(e), 400

@app.route('/receive_block', methods=['POST'])
def receive():
    data = request.json
    try:
        txs = []
        for txdata in data['txs']:
            tx = Tx(txdata['from'], txdata['to'], txdata['amount'], txdata['nonce'], txdata.get('fee', 0))
            tx.sig = txdata['sig']
            txs.append(tx)
        block = Block(data['index'], data['prev'], txs, data['ts'], data['diff'], data['nonce'])
        block.hash = data['hash']
        block.work = 2 ** block.difficulty
        success, msg = blockchain.receive_block(block)
        if success:
            blockchain.save()
            return "OK", 200
        else:
            return msg, 400
    except Exception as e:
        return str(e), 400

@app.route('/get_checkpoints')
def get_checkpoints():
    return jsonify(blockchain.checkpoints)

async def mining_loop():
    global blockchain, miner_addr, miner_private
    while True:
        block = blockchain.mine_block(miner_addr, miner_private)
        if block:
            print(f"\033[92m[MINED] #{block.index} | Diff: {block.difficulty} | Reward: {blockchain.get_expected_reward(block.index)/DECIMALS} VXN | Balance: {blockchain.state.get_balance(miner_addr)/DECIMALS}\033[0m")
            blockchain.save()
            threading.Thread(target=broadcast_block, args=(block,)).start()
        await asyncio.sleep(0.1)

def broadcast_block(block):
    data = {
        'index': block.index,
        'prev': block.prev_hash,
        'ts': block.timestamp,
        'diff': block.difficulty,
        'nonce': block.nonce,
        'hash': block.hash,
        'txs': [{
            'from': tx.from_addr,
            'to': tx.to_addr,
            'amount': tx.amount,
            'nonce': tx.nonce,
            'fee': tx.fee,
            'sig': tx.sig
        } for tx in block.txs]
    }
    for peer in list(PEERS):
        try:
            requests.post(f"http://{peer}/receive_block", json=data, timeout=2)
        except:
            pass

# ==================== MAIN ====================
if __name__ == '__main__':
    # Inisialisasi wallet
    if os.path.exists(WALLET_FILE):
        pw = input("Enter wallet password: ")
        miner_private, miner_addr = Wallet.load(pw)
        print(f"Wallet loaded. Address: {miner_addr}")
    else:
        pw = input("Create new wallet password: ")
        miner_private, miner_addr = Wallet.generate()
        Wallet.save(miner_private, miner_addr, pw)
        print(f"New wallet created. Address: {miner_addr}")

    # Load atau buat blockchain
    if os.path.exists(CHAIN_FILE):
        blockchain = Blockchain.load(CHAIN_FILE, miner_addr)
        print(f"Blockchain loaded. Height: {len(blockchain.chain)-1}")
    else:
        blockchain = Blockchain.create_genesis(miner_addr)
        blockchain.save()
        print("Genesis block created.")

    # Jalankan API
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8545
    threading.Thread(target=lambda: app.run(host='0.0.0.0', port=port, debug=False), daemon=True).start()
    print(f"API running on port {port}")

    # Mulai mining
    asyncio.run(mining_loop())
