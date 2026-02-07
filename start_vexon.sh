#!/data/data/com.termux/files/usr/bin/bash

echo "🚀 NYALAKKE EKOSISTEM VEXON L1..."

# 1. Jalankan Jantung (RPC) ning background
python VEXON_L1.py > /dev/null 2>&1 &
echo "✅ Jantung (RPC) wis aktif."

# 2. Jalankan Ledger (Mining/PoT) ning background
python ledger.py > /dev/null 2>&1 &
echo "✅ Ledger (Mining) wis aktif."

# 3. Jalankan Guard (Anti-Cheat)
python vexon_guard.py
echo "✅ Guard (Security) wis aktif."

echo "------------------------------------------"
echo "🔥 VEXON L1 IS RUNNING IN BACKGROUND!"
echo "💰 Saldo nambah terus, Jaringan Aman."
echo "Ketik 'pkill python' nek pengen mateni kabeh."
echo "------------------------------------------"

