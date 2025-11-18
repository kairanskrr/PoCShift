import os
import json
import hashlib
import pandas
import pymongo
import traceback
from tqdm import tqdm
from pocshift.databases.update_tracker import UpdateTacker
from pocshift.candidate_matching.utils import hashString
from pocshift.databases.constants import *
from pocshift.poc_abstraction.poc_abstraction import AbstractedPoC
from pocshift.candidate_matching.candidate_matching import CandidateMatching
from pocshift.solidityParser.contract_parser import parse_code
from dotenv import load_dotenv
load_dotenv()


class UpdatePoC:    
    def __init__(self):
        self.client = pymongo.MongoClient(os.getenv('MONGO_URI'))
        self.db = self.client[MONGO_DB]
        self.collection = self.db[POC_COLLECTION]
        self.tracker = UpdateTacker()
        self.tracker.initialization(POC_COLLECTION)
    
    def _insert_one(self, data, poc_info):
        hash = hashString(data['migratable_poc'])
        if self.collection.count_documents({'hash':hash}) == 0:
            entry_data = {
                'address':poc_info['vulnerable_address'],
                'chain':poc_info['chain'],
                'block_number':poc_info['block_number'],
                'lost':poc_info['lost'],
                'vulnerability':poc_info['taxonomy_mapping'],
                'link_reference':poc_info['link_reference'],
                'entry_point_address':poc_info['entry_point_address'],
                'entry_point_function_name':poc_info['entry_point_function_name'],
                'vuln_code':poc_info['vulnerable_code'],
                'vuln_function':poc_info['vuln_function'],
                'file_name':poc_info['file_name'],
                'vuln_code_hash':poc_info['vuln_code_hash'],
                'hash':hash,
                'migratable_poc':data['migratable_poc'],
                'migratable_poc_sig':data['migratable_poc_sig'],
                'abi':data['abi_summary'],
                "status": 0
            }
            self.collection.insert_one(entry_data)
            self.tracker.increment(POC_COLLECTION)
        else:
            self.collection.update_one({'hash':hash}, {'$set':{'vuln_code_hash':poc_info['vuln_code_hash']}})

    def collection_init(self):
        self.collection.create_index('hash', unique=True)
        self.collection.create_index('status')
        self.collection.create_index('index')
        self.collection.create_index([('address', pymongo.ASCENDING), ('chain', pymongo.ASCENDING)])
        self.collection.create_index('vulnerability')
        self.collection.create_index('vuln_code_hash')
    
    def insert(self, data, poc_info):
        to_be_inited = bool(self.collection.count_documents({}) == 0)
        self._insert_one(data, poc_info)
        if to_be_inited:
            self.collection_init()
            
    def batch_update(self, poc_dir, poc_info_df_path):
        poc_info_df = pandas.read_csv(poc_info_df_path)
        file_name_list = poc_info_df['file_name'].to_list()
        for file_name in file_name_list:
            if os.path.exists(os.path.join(poc_dir, file_name)):
                poc_template = open(os.path.join(poc_dir, file_name), 'r', encoding='utf-8').read()
                poc_sig = json.load(open(os.path.join(poc_dir, file_name.replace('.sol','.json')), 'r'))
                poc_sig['migratable_poc'] = poc_template
                poc_info = poc_info_df[poc_info_df['file_name']==file_name].to_dict('records')[0]
                parse_result = parse_code(poc_info['vulnerable_code'])
                if parse_result['functions']:
                    poc_info['vuln_code_hash'] = list(parse_result['functions'].values())[0]['hash']
                    self.insert(poc_sig, poc_info)
