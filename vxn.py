from flask import Flask, request, jsonify; from flask_cors import CORS; import time; app = Flask(__name__); CORS(app); F='0x1033B92B06ec683D9a55B5aD8F2dff13e64339bd'; G=1000000; S=1705410000; R=0.01;
def calc(a):
    el = time.time() - S
    if a.lower() == F.lower(): return G + (G * R * el / 31536000)
    m = 0.0003 * (el / 60)
    return m + (m * R * el / 31536000) if m >= 1000 else m
@app.route('/', methods=['GET', 'POST'])
def rpc():
    if request.method == 'GET': return 'VEXON L1 ONLINE'
    try:
        d = request.get_json(); m = d.get('method'); p = d.get('params', []); res = {'jsonrpc': '2.0', 'id': d.get('id', 1), 'result': None}
        if m == 'eth_getBalance': res['result'] = hex(int(calc(p[0] if p else '') * 10**18))
        elif m == 'eth_chainId': res['result'] = '0x22AD'
        elif m == 'eth_blockNumber': res['result'] = hex(int(time.time()))
        return jsonify(res)
    except: return jsonify({'error': 'invalid'})
if __name__ == '__main__':
    print('VEXON L1: MASTER NODE URIP SU!'); app.run(host='0.0.0.0', port=8545, threaded=True)
