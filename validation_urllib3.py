import sys
import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def test_legacy_crypto_logic():
    try:
        # 1. Test Cryptography Legacy API (default_backend is now deprecated/removed)
        # In v40+, this call will likely fail or behave differently
        backend = default_backend()
        digest = hashes.Hash(hashes.SHA256(), backend=backend)
        digest.update(b"ase-2026")
        print("✅ Cryptography backend check passed.")

        # 2. Test PyJWT Legacy API
        # Older code often decoded without explicitly forcing algorithms
        encoded = jwt.encode({"user": "aura"}, "secret", algorithm="HS256")
        # Modern PyJWT requires the 'algorithms' argument for security
        decoded = jwt.decode(encoded, "secret", algorithms=["HS256"])
        
        if decoded["user"] == "aura":
            print("✅ PyJWT functional check passed.")
            return True
        else:
            print("❌ Validation Failed: Data integrity error.")
            sys.exit(1)

    except TypeError as e:
        print(f"❌ Validation Failed: API Breakage (likely Cryptography). {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Validation Failed: Execution error. {e}")
        sys.exit(1)

if __name__ == "__main__":
    test_legacy_crypto_logic()