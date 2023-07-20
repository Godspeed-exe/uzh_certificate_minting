from pycardano import *
import hashlib


identity_hash = input("Enter your IdentityHash: ")
last_name = input("Enter your sur name: ")
cardano_testnet  = input("Enter your Cardano Testnet address: ")
signature  = input("Enter the signature of your certificate: ")
public_key  = input("Enter the public key of the signer: ")



signed_message = {
    "signature": signature,
    "key": public_key,
}

result = cip8.verify(signed_message=signed_message, attach_cose_key=True)

target_hash = hashlib.sha256(bytes(f"{identity_hash},{last_name},{cardano_testnet}","utf-8")).hexdigest()

if result["verified"]:
    print("This signature is verified correctly!")
    if result["message"] == target_hash:
        print("TargetHash matches as well! ")
else:
    print("This signature is NOT correct!")

print(result)

