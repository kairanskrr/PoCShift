import json
import time
from datetime import datetime
import pymongo
from pocshift.databases.constants import *
from pocshift.databases.utils import establish_connection
from pocshift.solidityParser.contract_parser import parse_code
from pocshift.candidate_matching.feature_filtering import feature_filtering_batch,feature_filtering
from pocshift.databases.update_tracker import UpdateTacker

'''
    initiator: contracts/poc
        contracts: ensure poc is not doing update and use contracts with status 0 to match all poc
        poc: ensure clone detector is not running and use newly inserted poc to match contracts with status 1
'''

class CandidateMatching:
    def __init__(self, threshold=0.8):
        '''
            pocs: status (0 means not updated, 1 means updated)
            contracts: status (0 means not updated, 1 means updated)
        '''
        self.threshold = threshold
        self.db = establish_connection()
        self.output = []
        self.matching_running = 0
        self.tracker = UpdateTacker()
        self.tracker.initialization(MATCHING_RUNNING_STATUS)
        
        self.contracts = 0
        self.pocs = 0
        
        
    def retrieve_project_list(self, index):
        output = []
        try:
            if self.db[CONTRACT_COLLECTION].count_documents({'index': index,'status':self.contracts}) > 0:
                entry = self.db[CONTRACT_COLLECTION].find_one({'index': index,'status':self.contracts})
                output.append((entry['hash'],entry['abi']))
        except:
            pass
        return output        


    # def check_with_db_for_similar_match(self, hash, expected_score):
    #     output = []
    #     for function in list(self.db[FUNCTION_COLLECTION].find()):
    #         func_hash = function['hash']
    #         score = tlsh.diffxlen(hash, func_hash)
    #         if score < expected_score:
    #             parent_list = function['parent_index']
    #             for p in parent_list:
    #                 retrieved_parent_list = self.retrieve_project_list(p)
    #                 temp = []
    #                 for p in retrieved_parent_list:
    #                     p['score'] = score
    #                     temp.append(p)
    #                 output.extend(temp)
    #     return output
    
    def check_subcontract(self, index):
        output = []
        index = int(index[1:])
        if self.db[SUBCONTRACT_COLLECTION].count_documents({'index': index}) > 0:
            parent_list = self.db[SUBCONTRACT_COLLECTION].find_one({'index':index})['parent_index']
            for parent in parent_list:
                output.extend(self.retrieve_project_list(parent))
        return output


    def check_with_db_for_exact_match(self, hash):
        output = []
        if self.db[FUNCTION_COLLECTION].count_documents({'hash': hash}) > 0:
            parent_list = self.db[FUNCTION_COLLECTION].find_one({'hash': hash})['parent_index']
            for parent in parent_list:
                output.extend(self.check_subcontract(parent))
        return output
    
    def get_template_with_code(self, vuln_code, abi):
        output = []
        parse_result = parse_code(vuln_code)
        for contract in parse_result['contracts']:
            for function in contract['functions']:
                if self.db[POC_COLLECTION].count_documents({'vuln_code_hash':function['hash']}) > 0:
                    poc = self.db[POC_COLLECTION].find_one({'vuln_code_hash':function['hash']})
                    if feature_filtering(poc,abi):
                        output.append(poc)
        for function in parse_result['functions']:
            if self.db[POC_COLLECTION].count_documents({'vuln_code_hash':parse_result['functions'][function]['hash']}) > 0:
                poc = self.db[POC_COLLECTION].find_one({'vuln_code_hash':parse_result['functions'][function]['hash']})
                if feature_filtering(poc,abi):
                    output.append(poc)
        return output
    
    def detect_batch(self):
        output = {}
        poc_list = list(self.db[POC_COLLECTION].find({'status':self.pocs}))
        for poc in poc_list:
            if 'vuln_code_hash' in poc:
                matching_result = self.check_with_db_for_exact_match(poc['vuln_code_hash'])
                feature_filtering_batch(poc, matching_result)
                if self.pocs == 0:
                    self.db[POC_COLLECTION].update_one({'_id':poc['_id']}, {'$set':{'status':1}})
                output[poc['file_name']] = matching_result
        if output:
            with open(f'./logs/candidate_matching/matching_output{datetime.now().strftime("%m-%d-%Y-%H-%M-%S")}.json', 'w') as f:
                f.write(json.dumps(output, indent=4))
        
    def detect_batch_by_contract(self):
        while(self.tracker.get_matching_status() == 1):
            time.sleep(300)
        self.tracker.set_matching_status(1)   
        self.pocs = 1
        self.contracts = 1 # 0 means waiting for detect, 1 means queing, 2 means done
        self.db[CONTRACT_COLLECTION].update_many({'status':0}, {'$set':{'status':1}})
        self.detect_batch()
        self.db[CONTRACT_COLLECTION].update_many({'status':1}, {'$set':{'status':2}})
        self.tracker.set_matching_status(0)    

    def detect_batch_by_poc(self):     
        while(self.tracker.get_matching_status() == 1):
            time.sleep(300)
        self.tracker.set_matching_status(1)   
        self.pocs = 0
        self.contracts = 2
        self.detect_batch()
        self.tracker.set_matching_status(0)


    def run_with_clone_result(self, clone_result_path):
        from tqdm import tqdm
        clone_result = json.load(open(clone_result_path, 'r'))
        name_to_start = 'Starlink_exp'
        is_start = False
        for name in tqdm(clone_result):
            if name == name_to_start:
                is_start = True
            if is_start:    
                if self.db[POC_COLLECTION].count_documents({'file_name':f'{name}.sol'}) > 0:
                    poc = self.db[POC_COLLECTION].find_one({'file_name':f'{name}.sol'})
                    result = [(f'{i["address"].lower()}_{i["chain"]}',[]) for i in clone_result[name]]
                    feature_filtering_batch(poc, result)


