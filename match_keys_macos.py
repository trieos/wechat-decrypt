#!/usr/bin/env python3
"""Match found memory keys with actual DB file salts.
Reads config.json for paths, falls back to auto-detection."""
import os, json, hashlib, hmac, struct

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")

# Load config
if os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE) as f:
        _cfg = json.load(f)
    DB_DIR = os.path.dirname(_cfg["db_dir"])  # parent of db_storage
    DB_STORAGE = _cfg["db_dir"]
else:
    DB_DIR = os.path.expanduser("~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files")
    DB_STORAGE = None

RAW_KEYS = os.path.expanduser("~/wechat_keys_raw.json")
OUT_FILE = os.path.join(SCRIPT_DIR, "all_keys.json")

# Find the user's db_storage dir
# Find the user's db_storage dir
if DB_STORAGE and os.path.isdir(DB_STORAGE):
    user_dirs = [(os.path.basename(os.path.dirname(DB_STORAGE)), DB_STORAGE)]
else:
    user_dirs = []
    for entry in os.listdir(DB_DIR):
        db_storage = os.path.join(DB_DIR, entry, "db_storage")
        if os.path.isdir(db_storage) and entry != "all_users":
            user_dirs.append((entry, db_storage))

if not user_dirs:
    print("No db_storage found!")
    exit(1)

print(f"Found user dirs: {[u[0] for u in user_dirs]}")

# Load raw keys from memory scan
raw_keys = json.load(open(RAW_KEYS))
print(f"Loaded {len(raw_keys)} raw key/salt pairs from memory scan")

# Scan all .db files and read their salts
results = {}
for user_id, db_storage in user_dirs:
    print(f"\nScanning {db_storage}...")
    for root, dirs, files in os.walk(db_storage):
        for fname in files:
            if not fname.endswith('.db'):
                continue
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, db_storage)
            
            try:
                with open(fpath, 'rb') as f:
                    salt = f.read(16)
                if len(salt) < 16:
                    continue
                salt_hex = salt.hex()
                size_mb = os.path.getsize(fpath) / (1024*1024)
                
                # Match against memory-found keys
                if salt_hex in raw_keys:
                    enc_key = raw_keys[salt_hex]["enc_key"]
                    
                    # HMAC verification (same as Windows version)
                    enc_key_bytes = bytes.fromhex(enc_key)
                    mac_salt = bytes(a ^ 0x3a for a in salt)
                    mac_key = hashlib.pbkdf2_hmac('sha512', enc_key_bytes, mac_salt, 2, dklen=32)
                    
                    with open(fpath, 'rb') as f:
                        page = f.read(4096)
                    
                    if len(page) == 4096:
                        hmac_data = page[:4096-32-16]  # exclude reserve (16 IV + 64 HMAC, but reserve=80)
                        # Actually: page has salt(16) + encrypted(4096-16-80) + IV(16) + HMAC(64)
                        reserve = 80
                        iv = page[4096-reserve:4096-reserve+16]
                        stored_hmac = page[4096-reserve+16:4096-reserve+16+64]
                        
                        # Compute HMAC: data = page[16:4096-reserve] + IV + page_number(le32)
                        hmac_msg = page[16:4096-reserve] + iv + struct.pack('<I', 1)
                        computed = hmac.new(mac_key, hmac_msg, hashlib.sha512).digest()
                        
                        if computed == stored_hmac:
                            print(f"  [MATCH+HMAC OK] {rel}: salt={salt_hex}, key={enc_key[:16]}... ({size_mb:.1f}MB)")
                            results[rel] = {
                                "enc_key": enc_key,
                                "salt": salt_hex,
                                "size_mb": round(size_mb, 2)
                            }
                        else:
                            print(f"  [MATCH but HMAC FAIL] {rel}: salt={salt_hex}")
                    else:
                        print(f"  [MATCH, tiny file] {rel}: salt={salt_hex}")
                else:
                    print(f"  [NO KEY] {rel}: salt={salt_hex} ({size_mb:.1f}MB)")
            except PermissionError:
                print(f"  [PERM DENIED] {rel}")
            except Exception as e:
                print(f"  [ERROR] {rel}: {e}")

print(f"\n{'='*60}")
print(f"Results: {len(results)} databases matched + HMAC verified")
json.dump(results, open(OUT_FILE, 'w'), indent=2, ensure_ascii=False)
print(f"Saved to {OUT_FILE}")
