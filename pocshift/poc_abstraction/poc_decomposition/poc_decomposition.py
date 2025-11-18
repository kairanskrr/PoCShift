import re
import json
from pocshift.poc_abstraction.poc_decomposition.invocation_flow import InvocationFlow
from pocshift.solidityParser.loc_parser import get_loc_info
from pocshift.solidityParser.poc_parser import get_listener_from_file

class PoCDecomposition:
    def __init__(self, poc_file, poc_info):
        print(poc_file)
        self.poc_content = open(poc_file,'r',encoding='utf-8').read()
        self.loc_info = get_loc_info(self.poc_content)
        self.addr_var_pairs = get_listener_from_file(poc_file).get_address_variable_pairs()
        self.invocation_flow = InvocationFlow(poc_file).parse()
        self.poc_info = poc_info
        self.decomposed = {}
        self.simplified = []
        self.filtered = []
        self.contracts = []
        self.functions = []
        self.poc_logic = []
        self.address_poc = []
    
                
    def find_all_nodes(self, invocation_flow, address, function_name, path=[], results=None):
        if results is None:
            results = [] 
        for index, node in enumerate(invocation_flow):
            if node.get('address') == address and node.get('function_name') == function_name:
                results.append(path + [index])  
            if 'children' in node:
                self.find_all_nodes(node['children'], address, function_name, path + [index], results)
        return results  

    def locate_vulnerable_node(self):
        position = self.find_all_nodes(self.invocation_flow, self.poc_info['entry_point_address'], self.poc_info['entry_point_function_name'], [])
        if len(position) > 1:
            selected_position = []
            min_length = min([len(p) for p in position])
            for i in range(min_length):
                if len(set([p[i] for p in position])) == 1:
                    selected_position.append(position[0][i])
                else:
                    break
        else:
            selected_position = position[0][:-1] if len(position) > 0 else []
        return selected_position

    def get_precondition_by_position(self, invocation_flow, position, keep=False):
        if len(position) == 0:
            if keep:
                return invocation_flow
            else:
                return []
        
        precondition = invocation_flow[:position[0]]
        temp = invocation_flow[position[0]]
        if len(position) > 1:
            temp['children'] = self.get_precondition_by_position(temp['children'], position[1:], keep=True)
        else:
            temp['children'] = []
        precondition.append(temp)
        return precondition

    def get_attack_logic_by_position(self, position):
        current_node = self.invocation_flow  
        if len(position) == 0:
            return current_node
        for index in position:
            if 'children' in current_node:
                current_node = current_node['children'][index] 
            else:
                current_node = current_node[index]  
        if 'children' in current_node:
            return current_node['children']
        return current_node

    def get_post_condition_by_position(self, invocation_flow, position, keep=False):
        if len(position) == 0:
            if keep:
                return invocation_flow
            else:
                return []
        
        if position[0] + 1 < len(invocation_flow):
            post_condition = invocation_flow[position[0]+1:]
            
        else:
            post_condition = []

        temp = invocation_flow[position[0]]
        if len(position) > 1:
            temp['children'] = self.get_post_condition_by_position(temp['children'], position[1:], keep=True)
        else:
            temp['children'] = []
        post_condition = [temp] + post_condition
        return post_condition   
    
    def decompose(self):
        selected_position = self.locate_vulnerable_node()
        attack_logic = self.get_attack_logic_by_position(selected_position)
        precondition = self.get_precondition_by_position(self.invocation_flow, selected_position)
        post_condition = self.get_post_condition_by_position(self.invocation_flow, selected_position)
        index = 0
        while 'event_name' in attack_logic[index]:
            index += 1
        attack_logic = attack_logic[index:]
        self.decomposed = {
            'precondition':precondition,
            'attack_logic':attack_logic,
            'postcondition': post_condition
        }
        return self.decomposed
    
    ######################################DECOMPOSE (ABOVE)########################################
    ###############################################################################################
    ######################################SIMPLIFY (BELOW)#########################################

    @staticmethod
    def flatten_json(json_data):
        function_calls = []
        function_calls_simplified = []

        for entry in json_data:
            # drop_children = True
            # if ('children' in entry) and drop_children:
            #     entry = {k:v for k,v in entry.items() if k != 'children'}
            if 'function_name' in entry:
                if entry['function_name'] in ['balanceOf','decimals']:
                    continue
                function_calls.append(entry)
                function_calls_simplified.append(f"{entry['function_name']}")
            elif 'event_name' in entry:
                function_calls.append(entry)
                function_calls_simplified.append(f"{entry['event_name']}")
            elif entry['call_type'] == 'new_contract':
                function_calls.append(entry)
                function_calls_simplified.append(f"new {entry['contract_name']}")
        return function_calls, function_calls_simplified
    
    
    def process_poc(self):
        poc_lines = self.poc_content.split('\n')
        poc_logic_lines = []
        contract = {'functions':[]}
        for key in self.loc_info:
            if isinstance(self.loc_info[key], dict):
                if ('isMainContract' in self.loc_info[key]) and self.loc_info[key]['isMainContract']:
                    contract = self.loc_info[key]
                elif self.loc_info[key]['type'] != 'interface':
                    self.contracts.append('\n'.join(poc_lines[self.loc_info[key]['start_line']-1:self.loc_info[key]['end_line']]))
        for function in contract['functions']:
            if function in ['setUp','onERC721Received','onERC1155Received','fallback','receive','pancakeCall','executeOperation']:
                poc_logic_lines.extend(poc_lines[contract['functions'][function]['start_line']:contract['functions'][function]['end_line']])
            elif not function.startswith('test'):   
                self.functions.append(poc_lines[contract['functions'][function]['start_line']-1:contract['functions'][function]['end_line']])
        self.poc_logic = poc_logic_lines
        match = re.findall(r'0x[a-fA-F0-9]{40}', self.poc_content)
        self.address_poc = list(set(match))
    
    
    def check_with_poc_content(self, attack_logic):
        self.filtered = []
        for entry in attack_logic:
            if 'event_name' in entry:
                self.filtered.append(entry)
            elif entry['call_type'] in ['new_contract','vm']:
                self.filtered.append(entry)
            elif (entry['address'] in self.poc_content) and (entry['function_name'] in self.poc_content):
                self.filtered.append(entry)
            for child in entry['children']:
                if 'event_name' in child:
                    self.filtered.append(child)
                elif child['call_type'] in ['new_contract','vm']:
                    self.filtered.append(child)
                elif (child['address'] in self.poc_content) and (child['function_name'] in self.poc_content):
                    self.filtered.append(child)
                self.check_with_poc_content(child['children'])



    @staticmethod
    def count_repeating_patterns(function_calls, pattern):
        n = len(function_calls)
        m = len(pattern)
        count = 0
        last_index = 0
        for i in range(0, n, m):
            if function_calls[i:i+m] == pattern:
                count += 1
                last_index = i+m
            else:
                break
        return count, last_index


    def find_repeating_patterns(self, function_calls, start_index, repeating_patterns):
        current_head = None
        current_index = -1
        current_pattern = []

        for index, function_call in enumerate(function_calls[start_index:]):
            if current_head is None:
                current_pattern.append(function_call)
                current_head = function_call
                current_index = index
            elif function_call == current_head:
                step = len(current_pattern)
                next_pattern = function_calls[(index+start_index):(index+step+start_index)]
                if next_pattern == current_pattern:
                    count, last_index = self.count_repeating_patterns(function_calls[start_index+current_index:], current_pattern)
                    if count > 2:
                        repeating_patterns.append((current_pattern, current_index+start_index, count))
                        if (start_index+last_index) < len(function_calls):
                            return self.find_repeating_patterns(function_calls, start_index+last_index, repeating_patterns)
                        else:
                            return repeating_patterns
                    else:
                        break
            else:
                current_pattern.append(function_call)
        
        if (start_index + 1) < len(function_calls):
            return self.find_repeating_patterns(function_calls, start_index + 1, repeating_patterns)
        return repeating_patterns

    
    def simplify(self):
        flattened_function_calls, flattened_function_calls_simplified = self.flatten_json(self.decomposed['attack_logic'])
        identified_repeating_patterns = self.find_repeating_patterns(flattened_function_calls_simplified,0,[])
        gap = 0
        for repeating_pattern in identified_repeating_patterns:
            (pattern, index, count) = repeating_pattern
            if pattern not in[['approve']]:
                revised_index = index - gap
                flattened_function_calls = flattened_function_calls[:revised_index+len(pattern)] + flattened_function_calls[revised_index+len(pattern)*(count)-1:]
                gap = len(pattern)*(count-1) - 1
        self.simplified = flattened_function_calls
        return self.simplified

    def run(self):
        if self.invocation_flow is None:
            return {}
        self.process_poc()
        self.decompose()
        # self.check_with_poc_content(self.decomposed['attack_logic'])
        self.simplify()
        return {
            'decomposed': self.decomposed,
            'simplified': self.simplified,
            # 'filtered': self.filtered,
            'poc_logic': '\n'.join(self.poc_logic),
            # 'functions': self.functions,
            # 'contract': self.contracts,
            'poc': {
                'functions':self.functions,
                'contracts':self.contracts,
                'address_list':self.address_poc,
                'poc_logic':self.poc_logic,
                'address_var_pairs':self.addr_var_pairs
            }
        }


