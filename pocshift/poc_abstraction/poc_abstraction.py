import os
import re
import json
from pocshift.poc_abstraction.poc_decomposition.poc_decomposition import PoCDecomposition
from pocshift.poc_abstraction.address_recovery.address_recovery import AddressRecovery
from pocshift.poc_abstraction.condition_translation.condition_translation import ConditionTranslation
from pocshift.poc_abstraction.utils.fetch_abi import fetch_contract_abi
from pocshift.poc_abstraction.utils.utils import process_type
POC_TEMPLATE_PATH = './templates/poc_template.sol'

class AbstractedPoC:
    def __init__(self, poc, poc_info, output_path=None):
        self.poc = poc
        self.poc_info = poc_info
        self.output_path = output_path
        
        self.decomposed_poc = {}
        self.identified_address = {}
        self.var_index_pairs = {}
        self.translated_condition = {}
        self.migratable_poc_sig = {}
        self.target_function_call = []
    
    @staticmethod          
    def get_distinct_address_list(attack_logic):
        output = set()
        for i in attack_logic:
            if 'address' in i:
                output.add(i['address'])
        return output

    def prepare_abi(self, abi_data={}):
        temp_abi_summary = './data_collection/abi_summary'
        poc_name = self.poc.split('/')[-1].strip().replace('.sol','.json')
        if os.path.exists(os.path.join(temp_abi_summary,poc_name)):
            with open(os.path.join(temp_abi_summary,poc_name), 'r') as f:
                abi_data = json.load(f)
        output = {}
        address_list = self.identified_address['address_dict']
        for i in address_list:
            if address_list[i]['index'] in ['$address(this)','$COMMONADDRESS', '$TEMPADDRESS', '$PAIRADDRESS']:
                continue
            if i in abi_data:
                abi = abi_data[i]
            else:
                abi = fetch_contract_abi(i, self.poc_info['chain'])
            if abi:
                output[i] = abi
        return output

    def generate_address_declaration(self):
        address_list = self.identified_address['address_dict']
        address_declaration = []
        address_initiation_dict = {'target':[],'common':[],'read':[],'temp':[],'pair':[]}
        for address in address_list:
                address_dict = address_list[address]
                if address_dict['index'] == '$TARGETADDRESS':
                    address_declaration.append(f'I{address_dict["index"][1:]} TARGETADDRESS;')
                    address_initiation_dict['target'].append(f'{address_dict["index"][1:]} = I{address_dict["index"][1:]}($TARGETADDRESS_PLACEHOLDER$);')
                elif '$COMMONADDRESS' in address_dict['index']:
                    index = address_dict['relation'][0]
                    if index == 0:
                        address_initiation_dict['common'].append(f'{address_dict["index"][1:]} = Uni_Router_V2(_commonrouterS);')
                        address_declaration.append(f'Uni_Router_V2 {address_dict["index"][1:]};')
                    else: 
                        address_initiation_dict['common'].append(f'{address_dict["index"][1:]} = IERC20(_commonmainTokenS[{index-1}]);')
                        address_declaration.append(f'IERC20 {address_dict["index"][1:]};')
                elif '$TEMPADDRESS' in address_dict['index']:
                    address_declaration.append(f'{address_dict["relation"][0][0]} {address_dict["index"][1:]};')
                    address_initiation_dict['temp'].append(f'{address_dict["index"][1:]} = new {address_dict["relation"][0][0]}();')
                elif '$READADDRESS' in address_dict['index']:
                    address_declaration.append(f'I{address_dict["index"][1:]} {address_dict["index"][1:]};')
                    address_initiation_dict['read'].append(f'{address_dict["index"][1:]} = I{address_dict["index"][1:]}(TARGETADDRESS.{address_dict["relation"][0]}());')
                    self.target_function_call.append([address_dict["relation"][0]])
                elif '$PAIRADDRESS' in address_dict['index']:
                    address_declaration.append(f'Uni_Pair_V2 {address_dict["index"][1:]};')
                    address_initiation_dict['pair'].append(f'{address_dict["index"][1:]} = Uni_Pair_V2(IUniswapV2Factory(Uni_Router_V2(_commonrouterS).factory()).getPair(address({address_dict["relation"][0][0]}), address({address_dict["relation"][0][1]})));')
        
        address_initiation = [j for i in address_initiation_dict.values() for j in i]
        return address_declaration, address_initiation
                
    def generate_interface_function_based_on_abi_entry(self, abi_entry):
        if abi_entry['type'] == 'function':
            inputs = ', '.join([
                process_type(input.get('internalType', input['type']), input['name'])
                for input in abi_entry.get('inputs', [])
            ])
            outputs = ', '.join([
                process_type(output.get('internalType', output['type']), '')
                for output in abi_entry.get('outputs', [])
            ])
            if ('struct' in inputs) or ('struct' in outputs):
                return ''
            state_mutability = f" {abi_entry['stateMutability']}" if 'stateMutability' in abi_entry else ""
            if state_mutability == " nonpayable":
                state_mutability = ""
            if outputs:
                return f"    function {abi_entry['name']}({inputs}) external{state_mutability} returns ({outputs});\n" 
            else:
                return f"    function {abi_entry['name']}({inputs}) external{state_mutability};\n"  
        return ''

    def generate_interface(self, abi_summary):
        output = {}
        address_summary = self.identified_address['address_dict']
        for address in address_summary:
            if address_summary[address]['type'] in ['address(this)', 'common', 'temp', 'pair']:
                continue
            if address not in abi_summary:
                output[address] = f'interface I{address_summary[address]["index"][1:]} {{\n}}\n'
                continue
            temp_output = []
            address_abi = abi_summary[address]
            function_calls = []
            keyword = address_summary[address]['type']
            # for keyword in ['target','common','read','pair','temp']:
            if address in self.migratable_poc_sig[keyword]:
                function_calls = set(self.migratable_poc_sig[keyword][address]['function_call'])
                    # break
            for entry in address_abi:
                if (entry['type'] != 'function') or (entry['name'] not in function_calls):
                    continue
                processed_entry = self.generate_interface_function_based_on_abi_entry(entry)
                if processed_entry:
                    temp_output.append(processed_entry)
            if temp_output:
                temp_output.insert(0, 'interface #INTERFACENAME {\n'.replace('#INTERFACENAME', f"I{address_summary[address]['index'][1:]}"))
                temp_output.append('}\n')
            output[address] = ''.join(temp_output)

        return output

    def get_function_call(self,address):
        output = []
        for i in self.decomposed_poc['simplified']:
            if ('address' in i) and ('function_name' in i):
                if i['address'] == address:
                    output.append(i['function_name'])
        return output

    def generate_migratable_poc_signature(self):
        output = {
            'target':{},
            'common':{},
            'read':{},
            'pair':{},
            'temp':{},
            'left':{}
        }
        for addr in self.identified_address['address_dict']:
            function_calls_temp = self.get_function_call(addr)
            relation = self.identified_address['address_dict'][addr]['relation'] if 'relation' in self.identified_address['address_dict'][addr] else []
            sig_temp = {
                'relation': relation,
                'function_call': function_calls_temp
            }
            if '$TARGETADDRESS' in self.identified_address['address_dict'][addr]['index']:
                output['target'][addr] = sig_temp
                output['target'][addr]['function_call'].extend(self.target_function_call)
            elif '$COMMONADDRESS' in self.identified_address['address_dict'][addr]['index']:
                output['common'][addr] = sig_temp
            elif '$READADDRESS' in self.identified_address['address_dict'][addr]['index']:
                output['read'][addr] = sig_temp
            elif '$PAIRADDRESS' in self.identified_address['address_dict'][addr]['index']:
                output['pair'][addr] = sig_temp
            elif '$TEMPADDRESS' in self.identified_address['address_dict'][addr]['index']:
                output['temp'][addr] = sig_temp
            else:
                output['left'][addr] = sig_temp
        self.migratable_poc_sig = output
        return output       
        
        
    def generate_migratable_poc(self):
        abi_summary = self.prepare_abi()
        address_declaration, address_initiation = self.generate_address_declaration()
        interface = self.generate_interface(abi_summary)
        attack_logic = self.translated_condition['attack_logic']
        precondition = self.translated_condition['precondition']
        postcondition = self.translated_condition['postcondition']
        
        interface_placeholders = list(interface.values())
        interface_placeholders.extend(self.decomposed_poc['poc']['contracts'])
            

        with open(POC_TEMPLATE_PATH, 'r') as f:
            template = f.read()
            template = template.replace('$INTERFACE_PLACEHOLDER$', '\n\n\n'.join(interface_placeholders))
            template = template.replace('$GLOBAL_DECLEATION_PLACEHOLDER$', '')
            template = template.replace('$VARIABLE_DECLEATION_PLACEHOLDER$', '\t' + '\n\t'.join(address_declaration))

            setup = address_initiation
            setup.extend(precondition)
            template = template.replace('$SETUP_PLACEHOLDER$', '\t\t' + '\n\t\t'.join(setup))

            function = postcondition['pre']
            function.extend(attack_logic)
            function.extend(postcondition['post'])
            template = template.replace('$FUNCTION_PLACEHOLDER$', '\t\t' + '\n\t\t'.join(function))
            
            helper_function = ''
            for func in self.decomposed_poc['poc']['functions']:
                if sum([1 for i in ['weth','wbn','usdt','to','usdc'] if i in func[0].lower()]) > 1:
                    continue
                helper_function += '\n'.join(func)
                helper_function += '\n\n'
            if helper_function:
                for var in self.var_index_pairs:
                    if var in helper_function:
                        helper_function = helper_function.replace(var, self.var_index_pairs[var][1:])
            template = template.replace('$HELPER_FUNCTION_PALCEHOLDER$', helper_function)
            
            return template, abi_summary
        
    def process_poc(self):
        self.decomposed_poc = PoCDecomposition(self.poc, self.poc_info).run()
        if not self.decomposed_poc:
            return
        address_recovery = AddressRecovery(self.poc, self.poc_info, self.decomposed_poc)
        self.identified_address = address_recovery.run()
        self.var_index_pairs = address_recovery.var_index_pairs
        self.translated_condition = ConditionTranslation(self.poc_info, self.decomposed_poc, self.identified_address).run()
            
    def run(self):
        self.process_poc()
        if not self.decomposed_poc:
            return
        migratable_poc_sig = self.generate_migratable_poc_signature()
        migratable_poc, abi_summary = self.generate_migratable_poc()
        
        output = {
            'migratable_poc': migratable_poc,
            'migratable_poc_sig': migratable_poc_sig,
            'abi_summary': abi_summary
        }
        if self.output_path:
            with open(self.output_path, 'w') as f:
                f.write(migratable_poc)
            with open(self.output_path.replace('.sol','.json'), 'w') as f:
                json.dump(output, f, indent=4)
        return output
    
    
