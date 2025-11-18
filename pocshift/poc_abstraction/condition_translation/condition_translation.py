import re
from copy import deepcopy
from pocshift.poc_abstraction.condition_translation.condition_mapping_table import transalte_event_to_constraints, process_param, process_param_value

class ConditionTranslation:
    
    def __init__(self, poc_info, poc_decomposed, address_list):
        self.poc_info = poc_info
        self.poc_decomposed = poc_decomposed
        self.precondition_flattened = self.flatten_json(deepcopy(poc_decomposed['decomposed']['precondition']))
        self.attack_logic_flattened = self.flatten_json(deepcopy(poc_decomposed['simplified']))
        self.postcondition_flattened = self.flatten_json(deepcopy(poc_decomposed['decomposed']['postcondition']))
        self.address_list = address_list['address_dict']
        self.address_list['0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496'] = {'index':'$address(this)','type':'address(this)'}

        self.identified_preconditions = {}
        self.identified_postconditions = {}
        
    def flatten_json(self, data, parent=None):
        output = []
        for entry in data:
            entry['parent'] = parent
            output.append(entry)
            if 'children' in entry:
                output.extend(self.flatten_json(entry['children'], entry))
        return output

    def process_vm_call(self, pre):
        if pre['keyword'] == 'deal':
            params = process_param(pre['params'])
            if len(params) == 2:
                return {
                    'address': params[0].split(':')[1].strip() if ':' in params[0] else params[0].strip(),
                    'amount': process_param_value(params[1]),
                    'action': 'deal'
                }
            else:
                pass
        elif pre['keyword'] == 'warp':
            params = process_param(pre['params'])
            if len(params) == 1:
                return {
                    'timestamp': params[0],
                    'action': 'warp'
                }
            else:
                pass
        elif pre['keyword'] == 'startPrank':
            params = process_param(pre['params'])
            if len(params) == 1:
                return {
                    'action': 'startPrank',
                    'address': params[0].split(':')[1].strip() if ':' in params[0] else params[0].strip()
                }   
            else:
                pass
        elif pre['keyword'] == 'stopPrank':
            return {
                'action': 'stopPrank'
            }
        pass

    def filter_preconditions_with_address_list(self, data):
        address_from_data = re.findall(r'0x[a-fA-F0-9]{40}', str(data))
        to_be_kept = True
        for address in address_from_data:
            if address not in self.address_list:
                to_be_kept = False
                break
        return to_be_kept

    def translate_precondition_single(self, pre, is_precondition=True):
        result = {}
        if 'event_name' in pre:
            result = transalte_event_to_constraints(pre, is_precondition)
        elif pre['call_type'] == 'vm':
            result = self.process_vm_call(pre)
            if result:
                result['precondition'] = is_precondition
        if result and self.filter_preconditions_with_address_list(result):
            return [result]
        return []

    def translate_precondition(self):
        result = []
        precondition = deepcopy(self.precondition_flattened)
        attack_logic = deepcopy(self.attack_logic_flattened)
        for pre in precondition:
            temp_result = self.translate_precondition_single(pre)
            if temp_result:
                result.extend(temp_result)
        for attack in attack_logic:
            temp_result = self.translate_precondition_single(attack, False)
            if temp_result:
                result.extend(temp_result)
        return result


    def process_condition(self, function_call):
        postcondition = []
        if function_call['call_type'] == 'staticcall':
            if 'decimal' not in function_call['function_name'].lower():
                postcondition.append({
                    'address': function_call['address'],
                    'function_name': function_call['function_name'],
                    'params': process_param(function_call['params'])
                })
        elif 'function_name' in function_call:
            if function_call['function_name'] == 'receive':
                postcondition.append({
                    'address': function_call['address'],
                    'function_name': 'receive'
                })
            elif 'receive' in function_call['function_name'].lower():
                postcondition.append({
                    'address': function_call['address'],
                    'function_name': 'receiveFlashloan',
                    'params': re.findall(r'.*?(0x[a-fA-F0-9]{40})', function_call['params'])
                })
        return postcondition

    def is_postcondition(postcondition, address_list):
        if postcondition['address'] in address_list:
            to_be_added = True
            if 'params' in postcondition:
                for param in postcondition['params']:
                    if isinstance(param, str) and param.startswith('0x'):
                        if param not in address_list:
                            to_be_added = False
                            break
        return to_be_added

    def filter_postcondition(self, postcondition):
        memo = []
        filtered_postcondition = []
        for post in postcondition:
            key = ''.join([str(i) for i in post.values()])
            if key in memo:
                continue
            memo.append(key)
            if post['address'] in self.address_list:
                to_be_added = True
                if 'params' in post:
                    for param in post['params']:
                        if isinstance(param, str) and param.startswith('0x'):
                            if param not in self.address_list:
                                to_be_added = False
                                break
                if to_be_added:
                    filtered_postcondition.append(post)
        return filtered_postcondition

    def translate_postcondition(self):
        processed_postcondition = []
        if self.postcondition_flattened:
            postcondition = deepcopy(self.postcondition_flattened)
            for post in postcondition:
                result = self.process_condition(post)
                if result:
                    processed_postcondition.extend(result)
        if len(processed_postcondition) == 0:
            attack_logic = deepcopy(self.attack_logic_flattened)
            for i in range(len(attack_logic)-1,-1,-1):
                if 'function_name' not in attack_logic[i]:
                    continue
                result = self.process_condition(attack_logic[i])
                if result:
                    processed_postcondition.extend(result)
                elif processed_postcondition:
                    break
        filtered_postcondition = self.filter_postcondition(processed_postcondition)
        if filtered_postcondition:
            processed_postcondition = filtered_postcondition
        return processed_postcondition


    def construct_attack_logic(self):
        output = []
        path_count = 0
        attack_logic = self.poc_decomposed['simplified']
        address_list = self.address_list
        for i in attack_logic:
            if 'address' in i:
                if i['address'] in address_list:
                    address_def = address_list[i['address']]['index'][1:]
                    function_name = i['function_name']
                    params = process_param(i['params'])
                    processed_params = []
                    to_be_saved = True
                    for param in params:
                        address_found = re.findall(r'.*?(0x[a-fA-F0-9]{40})', param)
                        for addr in address_found:
                            if addr == '0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496':
                                param = 'address(this)'
                            elif addr in address_list:
                                if address_list[addr]["index"] == 'address(this)':
                                    param = param.replace(addr, f'{address_list[addr]["index"][1:]}')
                                else:
                                    param = param.replace(addr, f'address({address_list[addr]["index"][1:]})')
                            else:
                                to_be_saved = False
                                break
                        match = re.match(r'^(\d+)\s+\[(\d+(?:\.\d+)?e[+-]?\d+)\]$', param, flags=re.IGNORECASE)
                        if match:
                            number = match.groups()[0]
                            param = re.sub(r'^(\d+)\s+\[(\d+(?:\.\d+)?e[+-]?\d+)\]$', number, param, flags=re.IGNORECASE)
                        if '[' in param:
                            param_eval = [p.strip() for p in param[1:-1].split(',')]
                            output.append(f'address[] memory PATH{path_count} = new address[]({len(param_eval)});')
                            for index, param_i in enumerate(param_eval):
                                output.append(f'PATH{path_count}[{index}]={param_i};')
                            processed_params.append(f'PATH{path_count}')
                            path_count += 1
                        else:
                            processed_params.append(param)
                    if to_be_saved:
                        if i['value'] is None:
                            output.append(f'{address_def}.{function_name}({",".join(processed_params)});')
                        else:
                            output.append(f'{address_def}.{function_name}{{value: {i["value"]}}}({",".join(processed_params)});')
        return output

    def convert_precondition_to_vm_ops(self, precondition):
        if precondition['action'] == 'transfer':
            action = 'deal'
            token = precondition['token']
            address = precondition['address']
            amount = precondition['amount']['value']
            
            if precondition['amount']['type'] != 'id':
                key = f'{action}_{token}_{address}'
                if key not in self.identified_preconditions:
                    self.identified_preconditions[key] = {
                        'action': action,
                        'token': token,
                        'address': address,
                        'amount': int(amount),
                    }
                else:
                    self.identified_preconditions[key]['amount'] += int(amount)
        elif precondition['action'] == 'approve':
            action = 'approve'
            token = precondition['token']
            caller = precondition['caller']
            callee = precondition['callee']
            amount = precondition['amount']['value']
            key = f'{action}_{token}_{caller}_{callee}'
            if key not in self.identified_preconditions:
                self.identified_preconditions[key] = {
                    'action': action,
                    'token': token,
                    'caller': caller,
                    'callee': callee,
                    'amount': 'type(uint256).max',
                }
        elif precondition['action'] == 'deposit':
            action = 'deposit'
            token = precondition['token']
            caller = precondition['caller']
            amount = precondition['amount']['value']
            key = f'{action}_{token}_{caller}'
            if key not in self.identified_preconditions:
                self.identified_preconditions[key] = {
                    'action': action,
                    'token': token,
                    'caller': caller,
                    'amount': int(amount),
                }
            else:
                self.identified_preconditions[key]['amount'] += int(amount)   
        elif precondition['action'] == 'deal':
            action = 'deal'
            token = precondition['token'] if 'token' in precondition else ''
            address = precondition['address']
            amount = precondition['amount']['value']
            key = f'{action}_{token}_{address}'
            if key not in self.identified_preconditions:
                self.identified_preconditions[key] = {
                    'action': action,
                    'token': token,
                    'address': address,
                    'amount': int(amount),
                }
            else:
                self.identified_preconditions[key]['amount'] += int(amount)
                
        elif (precondition['action'] == 'burn') and (not precondition['precondition']):
            action = 'deal'
            token = precondition['token']
            address = precondition['from']
            amount = precondition['amount']['value']
            key = f'{action}_{token}_{address}'
            if key not in self.identified_preconditions:
                self.identified_preconditions[key] = {
                    'action': action,
                    'token': token,
                    'address': address,
                    'amount': int(amount),
                }
            else:
                self.identified_preconditions[key]['amount'] += int(amount)
        elif precondition['action'] == 'withdraw':
            action = 'deal'
            token = precondition['token']
            address = precondition['from']
            amount = precondition['amount']['value']
            key = f'{action}_{token}_{address}'
            if key not in self.identified_preconditions:
                self.identified_preconditions[key] = {
                    'action': action,
                    'token': token,
                    'address': address,
                    'amount': int(amount),
                }
            else:
                self.identified_preconditions[key]['amount'] += int(amount)
        elif precondition['action'] in ['warp', 'mint','stopPrank']:
            pass
        else:
            pass         
        return self.identified_preconditions

    def generate_vm_op(self, precondition):
        if precondition['action'] == 'deal':
            if (precondition['token'] in self.address_list) and (precondition['address'] in self.address_list):
                address_index = self.address_list[precondition['address']]['index']
                if address_index == '$address(this)':
                    return [f'deal(address({self.address_list[precondition["token"]]["index"][1:]}), address(this), {precondition["amount"]});']
        elif precondition['action'] == 'approve':
            if (precondition['token'] in self.address_list) and (precondition['callee'] in self.address_list) and (precondition['caller'] in self.address_list):
                return [
                    f'vm.prank(address({self.address_list[precondition["caller"]]["index"][1:]}));',
                    f'{self.address_list[precondition["token"]]["index"][1:]}.approve(address({self.address_list[precondition["callee"]]["index"][1:]}), type(uint256).max);'
                    ]
        return []
        
    def construct_precondition(self, precondition):
        for pre in precondition:
            self.convert_precondition_to_vm_ops(pre)
        
        output = []
        for pre in self.identified_preconditions.values():
            output.extend(self.generate_vm_op(pre))
        return output


    def process_postcondition(self, postcondition):
        output = {
            'pre': [],
            'post': []
        }
        address_list = self.address_list
        if postcondition['function_name'] == 'balanceOf':
            if (postcondition['params'][0] in address_list) and (postcondition['address'] in address_list):
                output['pre'].append(f'uint preCheck = {address_list[postcondition["address"]]["index"][1:]}.balanceOf(address({address_list[postcondition["params"][0]]["index"][1:]}));')
                output['post'].append(f'uint postCheck = {address_list[postcondition["address"]]["index"][1:]}.balanceOf(address({address_list[postcondition["params"][0]]["index"][1:]}));')
                output['post'].append(f'require(postCheck > preCheck, "Postcondition failed");')
        elif postcondition['function_name'] == 'receive':
            if postcondition['address'] in address_list:
                output['pre'].append(f'uint preCheck = address({address_list[postcondition["address"]]["index"][1:]}).balance;')
                output['post'].append(f'uint postCheck = address({address_list[postcondition["address"]]["index"][1:]}).balance;')
                output['post'].append(f'require(postCheck > preCheck, "Postcondition failed");')
        elif postcondition['function_name'] == 'receiveFlashloan':
            for param in postcondition['params']:
                if isinstance(param, str) and param.startswith('0x'):
                    if (param in address_list) and (postcondition['address'] in address_list):
                        output['pre'].append(f'uint preCheck = {address_list[param]["index"][1:]}.balanceOf(address({address_list[postcondition["address"]]["index"]}));')
                        output['post'].append(f'uint postCheck = {address_list[param]["index"][1:]}.balanceOf(address({address_list[postcondition["address"]]["index"]}));')
                        output['post'].append(f'require(postCheck > preCheck, "Postcondition failed");')
        return output


    def constrcut_postcondition(self, postcondition):
        output = {
            'pre': [],
            'post': []
        }
        for post in postcondition:
            processed_post = self.process_postcondition(post)
            output['pre'].extend(processed_post['pre'])
            output['post'].extend(processed_post['post'])
        return output

    def run(self):
        precondition = self.translate_precondition()
        postcondition = self.translate_postcondition()
        
        constructed_precondition = self.construct_precondition(precondition)
        constructed_postcondition = self.constrcut_postcondition(postcondition)
        constructed_attack_logic = self.construct_attack_logic()
        return {
            'precondition':constructed_precondition,
            'attack_logic':constructed_attack_logic,
            'postcondition':constructed_postcondition
        }
    
    