import re
import json
from pocshift.poc_abstraction.address_recovery.address_mapping import identify_address_relationship
from pocshift.poc_abstraction.utils.constants import *
from copy import deepcopy

class AddressRecovery:
    
    def __init__(self, poc_path, poc_info, poc_decomposed):
        self.poc_path = poc_path
        self.poc_info = poc_info
        self.poc_decomposed = poc_decomposed
        self.finalized_address_dict = {}
        self.var_index_pairs = {}
    
    @staticmethod
    def generate_value(entry):
        if 'function_name' in entry:
            return f"{entry['function_name']}[call]"
        elif 'event_name' in entry:
            return f"{entry['event_name']}[event]"
        return ''

    def filter_address_dict(self, address_dict, temp_address_dict):
        address_to_ignore = list(temp_address_dict.keys())
        address_to_ignore.extend(['0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496'])
        filtered_address_dict = {}
        for address in address_dict:
            if address in [self.poc_info['vulnerable_address'], self.poc_info['entry_point_address']]:
                filtered_address_dict[address] = address_dict[address]
                continue
            if address in address_to_ignore:
                continue
            if len(address_dict[address]['in_degree']) == 0:
                for value in [f"{self.poc_info['entry_point_function_name']}[call]", f"{self.poc_info['vuln_function']}[call]"]:
                    if value in address_dict[address]['out_degree']:
                        filtered_address_dict[address] = address_dict[address]
                        break
                continue
            filtered_address_dict[address] = address_dict[address]
        return filtered_address_dict

    def match_with_address_in_poc(self, filtered_address_dict):
        content = open(self.poc_path,'r',encoding='utf-8').read()
        address_list = set(re.findall(r'\b0x[a-fA-F0-9]{40}\b', content))
        finalized_address_list = {}
        for addr in filtered_address_dict:
            if addr in address_list:
                finalized_address_list[addr] = filtered_address_dict[addr]
        return finalized_address_list

    def get_common_address_from_poc(self,finalized_address_dict):
        common_address = get_common_address(self.poc_info['chain'])
        for address in common_address:
            if address in self.poc_decomposed['poc']['address_list']:
                if address not in finalized_address_dict:
                    finalized_address_dict[address] = {'in_degree':[],'out_degree':[],'event':[]}
        return finalized_address_dict

    
    def extract_address_list(self):
        address_dict = {}
        temp_address_memo = {}
        to_be_examined = deepcopy(self.poc_decomposed['simplified'])
        to_be_examined.extend(self.poc_decomposed['decomposed']['precondition'])
        for entry in to_be_examined:
            if entry['call_type'] == 'new_contract':
                if entry['contract_address'] not in temp_address_memo:
                    temp_address_memo[entry['contract_address']] = []
                if entry['contract_name'] not in temp_address_memo[entry['contract_address']]:
                    temp_address_memo[entry['contract_address']].append(entry['contract_name'])
            if 'address' in entry:
                if entry['address'] not in address_dict:
                    address_dict[entry['address']] = {'in_degree':[],'out_degree':[],'event':[]}
                value = self.generate_value(entry)
                if value:
                    if value not in address_dict[entry['address']]['in_degree']:
                        address_dict[entry['address']]['in_degree'].append(value)
                    address_in_params = re.findall(r"\b0x[a-fA-F0-9]{40}\b", entry['params'])
                    for address in address_in_params:
                        if address not in address_dict:
                            address_dict[address] = {'in_degree':[],'out_degree':[],'event':[]}
                        if value not in address_dict[address]['out_degree']:
                            address_dict[address]['out_degree'].append(value)
        filtered_address_dict = self.filter_address_dict(address_dict, temp_address_memo)
        finalized_address_dict = self.match_with_address_in_poc(filtered_address_dict)
        if len(finalized_address_dict) > 0:
            finalized_address_dict = finalized_address_dict
        else:
            finalized_address_dict = filtered_address_dict
        finalized_address_dict = self.get_common_address_from_poc(finalized_address_dict)
        self.finalized_address_dict = {
            'address_dict': finalized_address_dict,
            'temp_address_dict': temp_address_memo
        }
        return self.finalized_address_dict
    
    def update_addr_var_pairs(self, identified_address, index):
        if self.poc_decomposed['poc']['functions']:
            if identified_address in self.poc_decomposed['poc']['address_var_pairs']:
                for entry in  self.poc_decomposed['poc']['address_var_pairs'][identified_address]:
                    if entry['variable_name']:
                        self.var_index_pairs[entry['variable_name']] = index
    
    def get_address_index(self, identified_address):
        temp_count = 0
        common_count = 0
        read_count = 0
        pair_count = 0
        left_count = 0
        for address in self.finalized_address_dict['address_dict']:
            if address in identified_address['address_identified']:
                addr_info = identified_address['address_identified'][address]
                if '$TARGETADDRESS' in addr_info:
                    self.finalized_address_dict['address_dict'][address]['index'] = '$TARGETADDRESS'
                    self.finalized_address_dict['address_dict'][address]['type'] = 'target'
                    self.update_addr_var_pairs(address, '$TARGETADDRESS')
                elif '$COMMONADDRESS' in addr_info:
                    self.finalized_address_dict['address_dict'][address]['index'] = f'$COMMONADDRESS{common_count}'
                    self.finalized_address_dict['address_dict'][address]['relation'] = addr_info[1:]
                    self.finalized_address_dict['address_dict'][address]['type'] = 'common'
                    self.update_addr_var_pairs(address, f'$COMMONADDRESS{common_count}')
                    common_count += 1
                elif '$READADDRESS' in addr_info:
                    self.finalized_address_dict['address_dict'][address]['index'] = f'$READADDRESS{read_count}'
                    self.finalized_address_dict['address_dict'][address]['relation'] = addr_info[1:]
                    self.finalized_address_dict['address_dict'][address]['type'] = 'read'
                    self.update_addr_var_pairs(address, f'$READADDRESS{read_count}')
                    read_count += 1
                elif '$PAIRADDRESS' in addr_info:
                    self.finalized_address_dict['address_dict'][address]['index'] = f'$PAIRADDRESS{pair_count}'
                    self.finalized_address_dict['address_dict'][address]['relation'] = addr_info[1:]
                    self.finalized_address_dict['address_dict'][address]['type'] = 'pair'
                    self.update_addr_var_pairs(address, f'$PAIRADDRESS{pair_count}')
                    pair_count += 1
                elif '$TEMPADDRESS' in addr_info:
                    self.finalized_address_dict['address_dict'][address]['index'] = f'$TEMPADDRESS{temp_count}'
                    self.finalized_address_dict['address_dict'][address]['relation'] = addr_info[1:]
                    self.finalized_address_dict['address_dict'][address]['type'] = 'temp'
                    self.update_addr_var_pairs(address, f'$TEMPADDRESS{temp_count}')
                    temp_count += 1
                else:
                    self.finalized_address_dict['address_dict'][address]['index'] = f'$LEFTADDRESS{left_count}'
                    self.finalized_address_dict['address_dict'][address]['type'] = 'left'
                    self.update_addr_var_pairs(address, f'$LEFTADDRESS{left_count}')
                    left_count += 1  
            else:
                self.finalized_address_dict['address_dict'][address]['index'] = f'$LEFTADDRESS{left_count}'
                self.finalized_address_dict['address_dict'][address]['type'] = 'left'
                self.update_addr_var_pairs(address, f'$LEFTADDRESS{left_count}')
                left_count += 1 
        for address in identified_address['address_identified']:
            addr_info = identified_address['address_identified'][address]
            if ('$TEMPADDRESS' in addr_info) and (address not in self.finalized_address_dict['address_dict']):
                self.finalized_address_dict['address_dict'][address] = {}
                self.finalized_address_dict['address_dict'][address]['index'] = f'$TEMPADDRESS{temp_count}'
                self.finalized_address_dict['address_dict'][address]['relation'] = addr_info[1:]
                self.finalized_address_dict['address_dict'][address]['type'] = 'temp'
                self.update_addr_var_pairs(address, f'$TEMPADDRESS{temp_count}')
                temp_count += 1
            
    
    def run(self):
        address_dict = self.extract_address_list()
        identified_address = identify_address_relationship(address_dict, self.poc_info)
        self.get_address_index(identified_address)
        return self.finalized_address_dict
    
    
    
