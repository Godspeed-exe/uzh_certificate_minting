from dotenv import load_dotenv
import mysql.connector
from pycardano import *
from blockfrost import BlockFrostApi, ApiError, ApiUrls,BlockFrostIPFS
import os
from os.path import exists
from PIL import Image, ImageFont, ImageDraw
import requests
import time
import csv
import hashlib



########################################################
#######           Loading ENV                    #######
########################################################
load_dotenv()
network = os.getenv('network')
mysql_host = os.getenv('mysql_host')
mysql_user = os.getenv('mysql_user')
mysql_password = os.getenv('mysql_password')
mysql_database = os.getenv('mysql_database')
wallet_mnemonic = os.getenv('wallet_mnemonic')
blockfrost_apikey = os.getenv('blockfrost_apikey')
blockfrost_ipfs = os.getenv('blockfrost_ipfs')
lock_policy_slot = int(os.getenv('lock_policy_slot'))

custom_header = {"project_id": blockfrost_ipfs}

def connect_to_db():
    global mydb 
    mydb = mysql.connector.connect(
        host=mysql_host,
        user=mysql_user,
        password=mysql_password,
        database=mysql_database,
        auth_plugin="mysql_native_password"
    )

connect_to_db()
mycursor = mydb.cursor(dictionary=True)


template_image = Image.open("assets/certificate.png")
font_size = 48
font = ImageFont.truetype('assets/SourceSansPro-Regular.otf', font_size)


text_length = 64 * (font_size/2)

x_coordinate = (template_image.width - text_length) / 2







########################################################
#######           Define Network                 #######
########################################################
if network=="testnet":
    base_url = ApiUrls.preprod.value
    cardano_network = Network.TESTNET
else:
    base_url = ApiUrls.mainnet.value
    cardano_network = Network.MAINNET

########################################################
#######           Initiate Blockfrost API        #######
########################################################
api = BlockFrostApi(project_id=blockfrost_apikey, base_url=base_url)        
cardano = BlockFrostChainContext(project_id=blockfrost_apikey, base_url=base_url)

########################################################
#######           Initiate wallet                #######
#######           Derive Address 1               #######
########################################################
new_wallet = crypto.bip32.HDWallet.from_mnemonic(wallet_mnemonic)
payment_key = new_wallet.derive_from_path(f"m/1852'/1815'/0'/0/0")
staking_key = new_wallet.derive_from_path(f"m/1852'/1815'/0'/2/0")
payment_skey = ExtendedSigningKey.from_hdwallet(payment_key)
staking_skey = ExtendedSigningKey.from_hdwallet(staking_key)

main_address=Address(payment_part=payment_skey.to_verification_key().hash(), staking_part=staking_skey.to_verification_key().hash(),network=cardano_network)

print(main_address)


with open('input.csv') as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=',')
    line_count = 0
    for row in csv_reader:
        if line_count > 0:
            first_name = row[0].strip()
            last_name = row[1].strip()
            cardano_address = row[2]
            cardano_testnet = row[3]

            identity_hash = hashlib.sha256(bytes(f"{first_name} {last_name}","utf-8")).hexdigest()    
            query = f"select * from students where identity_hash = '{identity_hash}' limit 1"
            mycursor.execute(query)
            student_exists = mycursor.fetchone()

            if student_exists is None:
                sql = "INSERT INTO students (first_name, last_name, cardano_address, cardano_testnet, identity_hash) VALUES (%s, %s, %s, %s, %s)"
                values = (first_name, last_name, cardano_address, cardano_testnet, identity_hash)
                mycursor.execute(sql, values)
                mydb.commit()
                print(f"Inserted '{first_name} {last_name}' with {identity_hash}")
            else:
                print(f"'{first_name} {last_name}' with '{identity_hash}' already existed")

        line_count += 1

query = f"select * from students where status = 0"
mycursor.execute(query)
all_students = mycursor.fetchall()

# confirmation = input(f"Found {len(all_students)} records to be minted. Continue? (y/n): ")

confirmation = 'y'

if confirmation == 'y':
    print("Continuing")


    ########################################################
    #######           Generate Policy keys           #######
    #######           IF it doesn't exist            #######
    ########################################################
    if not exists(f"keys/policy.skey") and not exists(f"keys/policy.vkey"):
        payment_key_pair = PaymentKeyPair.generate()
        payment_signing_key = payment_key_pair.signing_key
        payment_verification_key = payment_key_pair.verification_key
        payment_signing_key.save(f"keys/policy.skey")
        payment_verification_key.save(f"keys/policy.vkey")


    ########################################################
    #######           Initiate Policy                #######
    ########################################################
    policy_signing_key = PaymentSigningKey.load(f"keys/policy.skey")
    policy_verification_key = PaymentVerificationKey.load(f"keys/policy.vkey")
    pub_key_policy = ScriptPubkey(policy_verification_key.hash())

    must_before_slot = InvalidHereAfter(lock_policy_slot)
    policy = ScriptAll([pub_key_policy, must_before_slot])

    policy_id = policy.hash()
    policy_id_hex = policy_id.payload.hex()
    native_scripts = [policy]    
    base_name = "CERTIFICATE"
    for student in all_students:



        student_image = template_image.copy()
        student_draw = ImageDraw.Draw(student_image)

        first_name = student['first_name']
        last_name = student['last_name']
        cardano_address = student['cardano_address']
        cardano_testnet = student['cardano_testnet']
        identity_hash = student['identity_hash']
        asset_id = student['id']


        student_draw.text((x_coordinate,450), identity_hash, (255,255,255), font=font)

        file_name = f'assets/student_{identity_hash}.png'
        student_image.save(file_name)

        with open(file_name, 'rb') as f:
            res = requests.post("https://ipfs.blockfrost.io/api/v0/ipfs/add", headers= custom_header, files={file_name: f})
            hashed_char = res.json()['ipfs_hash']

        print(f"ipfs://{hashed_char}")


        builder = TransactionBuilder(cardano)
        builder.ttl = lock_policy_slot
        asset_name = f"{base_name}{asset_id:04d}"
        target_hash = hashlib.sha256(bytes(f"{first_name} {cardano_testnet}","utf-8")).hexdigest()
        print(target_hash)

        metadata = {
                    721: {  
                        policy_id_hex: {
                            asset_name: {
                                "name": "UZH BCC: DDiB 23",
                                "image": f"ipfs://{hashed_char}",
                                "Program": "Deep Dive into Blockchain 2023",
                                "Institution": "University of Zurich",
                                "description": [
                                    "https://files.ifi.uzh.ch/bdlt/cert/",
                                    "openbadges/courses/2023/course_description.json"
                                ]                                
                            }
                            
                        }
                    },
                    1870: {
                        "id": "https://files.ifi.uzh.ch/bdlt/cert/openbadges/issuer_id.json",
                        "type": "Assertion",
                        "badge": [
                            "https://files.ifi.uzh.ch/bdlt/cert/",
                            "openbadges/courses/2023/summerschool_blockchain_id.json"
                        ],
                        "@context": [
                            "https://w3id.org/openbadges/v2;",
                            "https://w3id.org/blockcerts/v2"
                        ],
                        "issuedOn": "2022-09-04T06:27:22Z",
                        "recipient": [
                            f"{identity_hash}",
                            {
                                "type": "IdentityHash",
                                "hashed": "true"
                            }
                        ],
                        "verification": {
                            "type": "signed",
                            "creator": "https://files.ifi.uzh.ch/bdlt/cert/openbadges/issuer_id.json",
                            "signature": [
                                "b2ba7c357c74ddd3a70c7f02ab942582738b97a028299bf4ede33d0d66d36967",
                                "b50c54ce91ac6174b0de8af992de4bf948742b0ff14e9a8585eefa2bf8b1e81a",
                                {
                                    "type": [
                                        "ECDSA",
                                        "Extension"
                                    ],
                                    "targetHash": target_hash
                                }
                            ],
                            "publicKeyOfCreator": [
                                "4cd4a3d6d6b493edd324c3df243342b28efbdaaa4f7c776ab818f84819f08909",
                                "f8c9491994f799465050e1a202a17d13d3b76289150792afbd3b6f4a3439195e"
                            ]
                        }
                    }
                }
        
        my_asset = Asset()
        my_nft = MultiAsset()

        

else:
    print("Exiting")
