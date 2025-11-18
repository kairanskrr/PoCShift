import os
import pandas
import pymongo
import traceback
from tqdm import tqdm
from dotenv import load_dotenv
from pocshift.databases.constants import *
load_dotenv()


class UpdateTacker:

    def __init__(self):
        self.client = pymongo.MongoClient(os.getenv('MONGO_URI'))
        self.db = self.client[MONGO_DB]
        self.collection = self.db[TRACKER_COLLECTION]
        
    def initialization(self, name):
        if self.collection.count_documents({'name':name}) == 0:
            if name == MATCHING_RUNNING_STATUS:
                self.collection.insert_one({'name':name, 'status':0})
            else:
                self.collection.insert_one({'name':name, 'count':0})
    
    def set_matching_status(self, status):
        self.collection.update_one({'name':MATCHING_RUNNING_STATUS}, {'$set':{'status':status}})
        
    def get_matching_status(self):
        return self.collection.find_one({'name':MATCHING_RUNNING_STATUS})['status']
    
    def increment(self, name):
        self.collection.update_one({'name':name}, {'$inc':{'count':1}})
    
    def init_batch(self):
        self.initialization(CONTRACT_COLLECTION)
        self.initialization(SUBCONTRACT_COLLECTION)
        self.initialization(FUNCTION_COLLECTION)
        self.initialization(STATEMENT_COLLECTION)
        self.initialization(GRAPH_COLLECTION)
        
        
    def set_index_for_colleciton(self, collection_name):
        try:
            self.db.create_collection(collection_name)
            collection = self.db[collection_name]
            if collection_name == CONTRACT_COLLECTION:
                collection.insert_one({'hash':'test','index':'test','status':'test'})
                collection.create_index('hash', unique=True)
                collection.create_index('index', unique=True)
                collection.create_index(['index', ('status', pymongo.ASCENDING)])
            else:
                collection.insert_one({'hash':'test','index':'test'})
                collection.create_index('hash', unique=True)
                collection.create_index('index', unique=True)
        except Exception as e:
            pass
    
    def set_index_batch(self):
        self.set_index_for_colleciton(CONTRACT_COLLECTION)
        self.set_index_for_colleciton(SUBCONTRACT_COLLECTION)
        self.set_index_for_colleciton(FUNCTION_COLLECTION)
        self.set_index_for_colleciton(STATEMENT_COLLECTION)
        self.set_index_for_colleciton(GRAPH_COLLECTION)