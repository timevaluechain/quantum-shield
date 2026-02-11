import hashlib, oqs, requests, time

# --- MEMBER CONFIG ---
MASTER_URL = "http://master-ip:8545" # IP Master lo, su!
MY_ADDR = "0xALAMAT_WALLET_MEMBER"    # Alamat Trust Wallet mereka

def solve_vexon_v4_1():
    print(f"\n[*] Vexon L1 | Mutual State Binding V4.1")
    print(f"[*] Wallet: {MY_ADDR[:15]}...")

    # 1. GENERATE LOCAL KEYPAIR
    with oqs.KeyEncapsulation("Kyber512") as member:
        pub_key = member.generate_keypair()
        
        # 2. REQUEST CHALLENGE & MASTER ANCHOR
        try:
            res = requests.post(f"{MASTER_URL}/get_state_challenge", 
                                json={"addr": MY_ADDR, "pub_key": pub_key.hex()})
            challenge = res.json()
            
            if res.status_code == 429:
                print(f"[!] Cooldown: {challenge.get('error')}")
                return
            elif "error" in challenge:
                print(f"[!] Denied: {challenge['error']}")
                return
        except:
            print("[!] Master Node Offline!"); return

        # 3. DECAPSULATE (The Kyber Proof)
        ciphertext = bytes.fromhex(challenge['ciphertext'])
        shared_secret = member.decap_secret(ciphertext)
        
        # 4. CONSTRUCT DOMAIN-BOUND PROOF
        method = "eth_getBalance"
        params_hash = hashlib.sha256(MY_ADDR.lower().encode()).hexdigest()
        epoch = challenge['epoch']
        nonce = challenge['nonce']
        
        # Domain Separation: VEXON_RPC_V4 | Biar gak bisa di-replay ke fitur lain
        proof_string = f"VEXON_RPC_V4|{shared_secret.hex()}|{nonce}|{method}|{params_hash}|{epoch}"
        proof = hashlib.sha3_512(proof_string.encode()).hexdigest()

        # 5. EXECUTE RPC
        payload = {"addr": MY_ADDR, "method": method, "proof": proof}
        final_res = requests.post(f"{MASTER_URL}/rpc", json=payload).json()
        
        if "result" in final_res:
            balance = int(final_res['result'], 16) / 10**18
            print(f"[+] SINKRON! Saldo: {balance:.8f} VXN")
            print(f"[+] Status: {final_res['status']}")
        else:
            print(f"[!] Auth Failed: {final_res.get('error')}")

if __name__ == "__main__":
    while True:
        solve_vexon_v4_1()
        # Sleep 30 detik biar sinkron per epoch Master
        time.sleep(30)
