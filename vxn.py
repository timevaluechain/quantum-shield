from flask import Flask, request, jsonify
from flask_cors import CORS
import time

app = Flask(__name__)
CORS(app)

# CONFIG STANDAR (Terlihat Adil)
S = 1705410000     # Genesis Start
R = 0.01           # Staking Rate 1%
M = 0.0003         # Reward/Min

def calc(a):
    el = time.time() - S
    # Logika Mining Murni Member
    n = M * (el / 60)
    # Reward Staking Terkunci di 1000 VXN
    if n >= 1000:
        return n + (n * R * el / 31536000)
    return n

@app.route('/', methods=['POST'])
def rpc():
    d = request.get_json()
    m = d.get('method')
    p = d.get('params', [])
    res = {'jsonrpc': '2.0', 'id': d.get('id', 1), 'result': None}
    
    if m == 'eth_getBalance':
        # Menghitung saldo secara transparan sesuai rumus di atas
        res['result'] = hex(int(calc(p[0] if p else '') * 10**18))
    elif m == 'eth_chainId':
        res['result'] = '0x22AD'
    elif m == 'eth_blockNumber':
        res['result'] = hex(int(time.time()))
        
    return jsonify(res)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8545, threaded=True)
