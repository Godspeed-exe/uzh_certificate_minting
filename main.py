from dotenv import load_dotenv
import mysql.connector
from pycardano import *
from blockfrost import BlockFrostApi, ApiError, ApiUrls,BlockFrostIPFS
import os
from os.path import exists
from PIL import Image
import requests
import time


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


