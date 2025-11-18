import os
import pymongo
from pocshift.databases.constants import *
from pocshift.databases.utils import *
from dotenv import load_dotenv
load_dotenv()

conn = pymongo.MongoClient(os.getenv('MONGO_URI'))
db = conn[MONGO_DB]

def get_contract_by_address_and_chain(address, chain):
    collection = db[CONTRACT_COLLECTION]
    result = collection.find_one({'address': address, 'chain': chain})
    return result

