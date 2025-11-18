import pymongo
from tqdm import tqdm
from pocshift.databases.constants import *
from pocshift.poc_abstraction.utils.fetch_abi import fetch_contract_abi
from pocshift.databases.utils import establish_connection

def feature_filtering(poc, abi):
    if abi:
        function_list = [entry['name'] for entry in abi if 'name' in entry] 
    else:
        function_list = []       
    function_required = list(poc['migratable_poc_sig']['target'].values())[0]['function_call']
    for addr in poc['migratable_poc_sig']['read']:
        function_required.extend(poc['migratable_poc_sig']['read'][addr]['relation'])
    for func in set(function_required):
        if func not in function_list:
            return False
    return True
    


def feature_filtering_batch(poc, address_list):
    db = establish_connection()
    output = []
    for entry in address_list:
        temp,abi = entry
        temp = temp.split('_')
        address = temp[0]
        chain = temp[1]
        if not abi:
            try:
                abi = fetch_contract_abi(address, chain)
            except Exception as e:
                abi = []
        if db[MATCHING_COLLECTION].count_documents({'address':address,'chain':chain,'poc_hash':poc['hash']}) > 0:
            continue
        if feature_filtering(poc, abi):
            entry = {
                'address':address,
                'chain':chain,
                'block_number':poc['block_number'],
                'poc_hash':poc['hash'],
                'address_hash':entry,
                'poc_template':poc['file_name'],
                'vulnerability':poc['vulnerability'],
                'status': 0
            }
            db[MATCHING_COLLECTION].insert_one(entry)
            output.append(entry)
    return output



def update_abi():
    db = establish_connection()
    contract_list = list(db[CONTRACT_COLLECTION].find({}))
    for contract in tqdm(contract_list):
        if 'abi' not in contract:
            try:
                address = contract['address'][0]
                if address.startswith('0x0x'):
                    address = address[2:]
                chain = contract['hash'].split('_')[1]
                abi = fetch_contract_abi(address, chain)
            except Exception as e:
                abi = []
            db[CONTRACT_COLLECTION].update_one({'index':contract['index']}, {'$set':{'abi':abi}})
            try:
                db[CONTRACT_COLLECTION].update_one({'index':contract['index']}, {'$set':{'address':[address],'hash':f'{address}_{chain}'}})
            except Exception as e:
                pass
if __name__ == '__main__':
    update_abi()