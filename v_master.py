import time, threading
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# --- LOGIKA MASTER VEXON L1 (DARI BASE64) ---
START_TIME = 1705410000 
MIN_STAKE_REQUIRED = 1000
STAKING_RATE = 0.01
INITIAL_REWARD_PER_MIN = 0.0003
HALVING_PERIOD = 5 * 365 * 86400

def get_r_key():
    # Whale Key
    return "078103333623932623036656336383336439613535623561643836363234363666313635363433333936323634"

def calculate_balance(addr=""):
    elapsed = time.time() - START_TIME
    if addr.lower() == get_r_key().lower():
        genesis = 1000000
        return genesis + (genesis * STAKING_RATE * (elapsed / 31536000))
    num_halvings = int(elapsed // HALVING_PERIOD)
    current_rate = INITIAL_REWARD_PER_MIN / (2 ** num_halvings)
    total_mined = current_rate * (elapsed / 60)
    if total_mined >= MIN_STAKE_REQUIRED:
        return total_mined + (total_mined * STAKING_RATE * (elapsed / 31536000))
    return total_mined

# --- RPC & P2P INTERFACE (Port 8545) ---
@app.route('/rpc', methods=['POST'])
def rpc():
    data = request.get_json()
    method = data.get('method')
    params = data.get('params', [])
    res = {"jsonrpc": "2.0", "id": data.get('id', 1), "result": None}
    
    if method == "eth_getBalance":
        addr = params[0] if params else ""
        res["result"] = hex(int(calculate_balance(addr) * 10**18))
    elif method == "eth_chainId":
        res["result"] = "0x22AD" # Chain ID Vexon
    elif method == "eth_blockNumber":
        res["result"] = hex(int(time.time()))
    return jsonify(res)

# --- DAPP DASHBOARD (Port 5000) ---
@app.route('/')
def index():
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>VEXON L1 - CONNECT WALLET</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <script src="https://cdn.jsdelivr.net/npm/web3@latest/dist/web3.min.js"></script>
        <style>
            body { background: #000; color: #fff; font-family: sans-serif; text-align: center; padding: 20px; }
            .card { border: 2px solid #ffd700; border-radius: 20px; padding: 25px; background: #111; box-shadow: 0 0 20px #ffd700; }
            .btn { background: #ffd700; color: #000; padding: 12px 25px; border: none; border-radius: 10px; font-weight: bold; cursor: pointer; font-size: 16px; }
            .status { color: #00ff00; font-size: 0.9em; margin-bottom: 20px; }
            #balance { font-size: 2.5em; color: gold; margin: 15px 0; }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>VEXON PROTOCOL L1</h1>
            <div id="connectionStatus" class="status">● Jaringan Lokal Aktif (P2P)</div>
            
            <button class="btn" id="connectBtn" onclick="connect()">CONNECT WALLET</button>
            
            <div id="walletInfo" style="display:none; margin-top: 20px;">
                <p>Alamat Dompet:</p>
                <code id="addr" style="color: #aaa;"></code>
                <div id="balance">0.00 VXN</div>
                <p>Harga: <b style="color:white;">$15,000 USD</b></p>
                <hr border="1" color="#333">
                <p style="font-size: 0.8em; color: gold;">STATUS MINING: AKTIF</p>
            </div>
        </div>

        <script>
        let web3;
        async function connect() {
            if (window.ethereum) {
                try {
                    // Paksa nyambung neng Jaringan Lokal (P2P Node)
                    await window.ethereum.request({
                        method: 'wallet_addEthereumChain',
                        params: [{
                            chainId: '0x22AD',
                            chainName: 'Vexon L1 P2P',
                            nativeCurrency: { name: 'VEXON', symbol: 'VXN', decimals: 18 },
                            rpcUrls: ['http://localhost:8545/rpc']
                        }]
                    });
                    
                    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
                    document.getElementById('connectBtn').style.display = 'none';
                    document.getElementById('walletInfo').style.display = 'block';
                    document.getElementById('addr').innerText = accounts[0];
                    
                    web3 = new Web3(window.ethereum);
                    const bal = await web3.eth.getBalance(accounts[0]);
                    document.getElementById('balance').innerText = (bal / 1e18).toFixed(4) + " VXN";
                    
                } catch (e) { alert("Gagal nyambung: " + e.message); }
            } else { alert("Pasang Trust Wallet dhisik, Cok!"); }
        }
        </script>
    </body>
    </html>
    '''
    return render_template_string(html)

if __name__ == '__main__':
    # Jalanake RPC neng port 8545 (nggo Connect Wallet)
    threading.Thread(target=lambda: app.run(host='0.0.0.0', port=8545, debug=False, use_reloader=False)).start()
    # Jalanake DApp neng port 5000 (nggo User)
    print("=== VEXON L1 READY ===")
    print("DApp: http://localhost:5000")
    print("RPC P2P: http://localhost:8545/rpc")
    app.run(host='0.0.0.0', port=5000, debug=False)

