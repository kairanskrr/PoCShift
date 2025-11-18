import os
import pymongo
import pandas
import traceback
from tqdm import tqdm
from pocshift.databases.update_tracker import UpdateTacker
from pocshift.databases.constants import *
from pocshift.databases.utils import *
from pocshift.solidityParser.contract_parser import parse_file
from pocshift.poc_abstraction.utils.fetch_abi import fetch_contract_abi
from dotenv import load_dotenv
load_dotenv()

class UpdateDatabase:

    def __init__(self, project_dir):
        self.client = pymongo.MongoClient(os.getenv('MONGO_URI'))
        self.db = self.client[MONGO_DB]
        self.tracker = UpdateTacker()
        self.tracker.init_batch()
        self.tracker.set_index_batch()
        
        self.project_dir = project_dir
        self.address = ''
        self.chain = ''
        self.hash = ''
        

    def processProjectSingle(self, path):
        if not path.endswith('.sol'):
            return
        try:
            contract_index = checkContractInDatabase(self.address, self.hash)
            if contract_index > 0:
                try:
                    abi = fetch_contract_abi(self.address, self.chain)
                except Exception as e:
                    abi = []
                subcontract_list = []
                function_list = []
                statement_dict = {}
                parse_output = parse_file(path)
                for subcontract in parse_output['contracts']:
                    index,statements_cached = saveSUBContractToDatabase(parse_output['contracts'][subcontract],contract_index)
                    if index > 0:
                        subcontract_list.append(index)
                        statement_dict.update(statements_cached)
                for function in parse_output['functions']:
                    index,statements_cached = saveFunctionToDatabase(parse_output['functions'][function],contract_index)
                    if index > 0:
                        function_list.append(index)
                        statement_dict.update(statements_cached)
                saveContractToDatabase(self.address, "", self.hash, contract_index, subcontract_list,function_list, statement_dict)
        except Exception as e:
            traceback.print_exc()


    def run(self):
        temp = os.path.normpath(self.project_dir).split(os.sep)[-1].split('_',1)
        self.address = temp[0].strip().strip("'")
        self.chain = temp[1].strip().strip("'").replace('.sol','')
        self.hash = f"{self.address}_{self.chain}"
                
        if os.path.exists(os.path.join(self.project_dir,'contracts')):
            project_dir = os.path.join(self.project_dir,'contracts')
        else:
            project_dir = self.project_dir

        content = ''
        for root, _, files in os.walk(project_dir):
            for file in tqdm(files, desc=root):
                if file.endswith('.sol'):
                    content += open(os.path.join(root, file), 'r').read()
                    content += '\n'
        with open(self.hash+'.sol', 'w') as f:
            f.write(content)
        self.processProjectSingle(self.hash+'.sol')
        os.remove(self.hash+'.sol')
                    

