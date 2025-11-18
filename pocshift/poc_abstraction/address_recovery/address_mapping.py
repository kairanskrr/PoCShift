import os
import re
import json
import pandas
import traceback
from tqdm import tqdm
from web3 import Web3
import logging
import subprocess
from pocshift.poc_abstraction.utils.constants import *
from pocshift.poc_abstraction.utils.fetch_abi import fetch_contract_abi

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',filename='./log.log', filemode='a')


#############################################################= RETRIEVE READ FUNCTIONS =#######################################################################
def get_read_functions(abi):
    try:
        output = []
        for item in abi:
            if item['type'] == 'function' and ('constant' in item or item['stateMutability'] == 'view') and (len(item['inputs']) == 0):
                if 'address' in [i['type'] for i in item['outputs']]:
                    output.append(item)
        return output
    except Exception:
        traceback.print_exc()
        return []

def process_type(type_name, name):
    special_types = ['string', 'bytes', '[]']
    for special_type in special_types:
        if special_type in type_name:
            return f"{type_name} memory {name}" 
    if 'contract' in type_name:
        return f"address {name}"           
    return f"{type_name} {name}"

def generate_interface_function_based_on_abi_entry(abi_entry):
    if abi_entry['type'] == 'function':
        inputs = ', '.join([
            process_type(input.get('internalType', input['type']), input['name'])
            for input in abi_entry.get('inputs', [])
        ])

        outputs = ', '.join([
            process_type(output.get('internalType', output['type']), '')
            for output in abi_entry.get('outputs', [])
        ])

        state_mutability = f" {abi_entry['stateMutability']}" if 'stateMutability' in abi_entry else ""
        if state_mutability == " nonpayable":
            state_mutability = ""

        return f"    function {abi_entry['name']}({inputs}) external {state_mutability} returns ({outputs});\n"    

def generate_read_function_checker(abi, chain, target_address, block_number, output_file_path):
    try:
        template = open(READ_FUNCTION_CHECKER_TEMPLATE, 'r').read()
        interface_placeholder = ''
        readfunction_placeholder = ''
        read_functions = get_read_functions(abi)
        for function in read_functions:
            if ('inputs' in function) and (len(function['inputs']) > 0):
                continue
            interface_placeholder += generate_interface_function_based_on_abi_entry(function)
            readfunction_placeholder += f"        console.log('{function['name']}:', token.{function['name']}());\n"
        template = template.replace('$INTERFACE_PLACEHOLDER$', interface_placeholder)
        template = template.replace('$READFUNCTION_PLACEHOLDER$', readfunction_placeholder)
        if block_number:
            template = template.replace('$CHAIN_BLOCK_PLACEHOLDER$', f"'{chain}'")
        else:
            template = template.replace('$CHAIN_BLOCK_PLACEHOLDER$', f"'{chain}',{block_number}")
        template = template.replace('$TARGETADDRESS_PLACEHOLDER$', target_address)
        with open(output_file_path, 'w', encoding='utf-8') as f:
            f.write(template)
        return True
    except Exception:
        traceback.print_exc()
        return False

def run_forge_test(file_path):
    try:
        command = ["forge", "test", "--contracts", os.path.join(file_path), '-vvv']
        result = subprocess.run(command, capture_output=True, text=True,timeout=3600)
        return result.stdout
    except Exception:
        traceback.print_exc()
        return None

def parse_read_function_checker_result(log):
    if 'Logs' not in log:
        return 
    project_output = {}
    read_function_list = log.split('Logs:')[-1].split('Suite result:')[0].strip().split('\n')
    for function in read_function_list:
        if ':' in function:
            split_temp = function.split(':')
            read_function = split_temp[0].strip()
            address = split_temp[1].strip()
            if address not in project_output:
                project_output[address] = read_function
            else:
                if len(project_output[address]) > len(read_function):
                    project_output[address] = read_function
    return project_output

def retrieve_read_function(address, vulnerability_info, abi=None):
    try:
        if abi is None:
            abi = fetch_contract_abi(address, vulnerability_info['chain'])
        if abi:
            if generate_read_function_checker(
                abi,
                vulnerability_info['chain'],
                address,
                vulnerability_info['block_number'],
                TEMP_CONTRACT_FILE_PATH
            ):
                result = run_forge_test(TEMP_CONTRACT_FILE_PATH)
                if result:
                    return parse_read_function_checker_result(result)
    except:
        traceback.print_exc()
        return
    

def generate_pair_address_checker(address_list, chain, block_number,output_file_path):
    try:
        factory_address = get_factory_address(chain)
        if factory_address is None:
            print(f"Factory address not found in {chain}.")
            return None
        common_address_list = get_common_address(chain)
        for addr in common_address_list:
            if addr not in address_list:
                address_list.append(addr)
        contract_template = open(PAIR_ADDRESS_CHECKER_TEMPLATE, 'r').read()
        contract_template = contract_template.replace('$FACTORY_PLACEHOLDER', factory_address)
        if block_number is not None:
            contract_template = contract_template.replace('$CHAIN_BLOCK_PLACEHOLDER', f"'{chain}',{block_number}")
        else:
            contract_template = contract_template.replace('$CHAIN_BLOCK_PLACEHOLDER', f"'{chain}'")

        CHECKING_CODE_TEMPLATE = '''
            address token0_index = TOKEN0ADDRESS_PLACEHOLDER;
            address token1_index = TOKEN1ADDRESS_PLACEHOLDER;
            address pair_index = IUniswapV2Factory(address(factory)).getPair(token0_index, token1_index);
            console.log("--------------------");
            console.log("pair:", pair_index);
            console.log("token0:", token0_index);
            console.log("token1:", token1_index);
        '''
        checking_code = ''
        index = 0
        for i in range(len(address_list)):
            for j in range(i+1, len(address_list)):
                checking_code += CHECKING_CODE_TEMPLATE.replace('index',f'{index}').replace('TOKEN0ADDRESS_PLACEHOLDER', address_list[i]).replace('TOKEN1ADDRESS_PLACEHOLDER', address_list[j])
                index += 1
        contract_template = contract_template.replace('$CHECKING_CODE_PLACEHOLDER', checking_code)
        with open(output_file_path, 'w', encoding='utf-8') as f:
            f.write(contract_template)
        return True
    except:
        traceback.print_exc()
        return False

def parse_pair_address_checker_result(log):
    pair_list = []
    pair_pattern = r"pair: (\w+)"
    token0_pattern = r"token0: (\w+)"
    token1_pattern = r"token1: (\w+)"
    if 'Logs:' in log:
        pair_list_raw = log.split('--------------------\n')[1:]
        for entry in pair_list_raw:
            pair_address = re.search(pair_pattern, entry).group(1)
            token0_address = re.search(token0_pattern, entry).group(1)
            token1_address = re.search(token1_pattern, entry).group(1)
            pair_list.append((pair_address, token0_address, token1_address))
    return pair_list

def retrieve_pair_address(address_list, chain, blocknumber):
    pair_list = []
    if generate_pair_address_checker(address_list, chain, blocknumber, TEMP_CONTRACT_FILE_PATH):
        result = run_forge_test(TEMP_CONTRACT_FILE_PATH)
        if result:
            pair_pattern = r"pair: (\w+)"
            token0_pattern = r"token0: (\w+)"
            token1_pattern = r"token1: (\w+)"
            if 'Logs:' in result:
                pair_list_raw = result.split('--------------------\n')[1:]
                for entry in pair_list_raw:
                    pair_address = re.search(pair_pattern, entry).group(1)
                    token0_address = re.search(token0_pattern, entry).group(1)
                    token1_address = re.search(token1_pattern, entry).group(1)
                    pair_list.append((pair_address, token0_address, token1_address))
    return pair_list

def identify_address_relationship(address_dict, vulnerability_info, abi=None):
    address_identified = {}
    address_memo = []
    target_address = vulnerability_info['vulnerable_address']
    if vulnerability_info['vulnerable_address'] in address_dict['address_dict']:
        address_identified[vulnerability_info['vulnerable_address']] = ['$TARGETADDRESS']
    elif vulnerability_info['entry_point_address'] in address_dict['address_dict']:
        address_identified[vulnerability_info['entry_point_address']] = ['$TARGETADDRESS']
        target_address = vulnerability_info['entry_point_address']
    else:
        address_identified[vulnerability_info['vulnerable_address']] = ['$TARGETADDRESS']
        address_dict['address_dict'][vulnerability_info['vulnerable_address']] = {}
    if len(address_dict['address_dict']) <= len(address_identified):
        return {
            'target_address':target_address,
            'address_identified':address_identified
        }
    common_address_list = get_common_address(vulnerability_info['chain'])
    if abi and (target_address in abi):
        read_function_info = retrieve_read_function(target_address, vulnerability_info, abi[target_address])
    else:
        read_function_info = retrieve_read_function(target_address, vulnerability_info)

    for address in address_dict['temp_address_dict']:
        address_identified[address] = ['$TEMPADDRESS',address_dict["temp_address_dict"][address]]
        if address not in address_memo:
            address_memo.append(address)
    for address in address_dict['address_dict']:
        if address in common_address_list:
            address_identified[address] = ['$COMMONADDRESS',common_address_list.index(address)]
        elif read_function_info and (address in read_function_info):
            address_identified[address] = ['$READADDRESS',read_function_info[address]]
    if len(address_dict['address_dict']) <= len(address_identified):
        return {
            'target_address':target_address,
            'address_identified':address_identified
        }    
    pair_address_list = retrieve_pair_address(address_memo, vulnerability_info['chain'], vulnerability_info['block_number'])
    for address in pair_address_list:
        if address[0] in address_identified:
            address_identified[address[0]].append(f'$PAIRADDRESS({address[1]},{address[2]})')
            for addr in address[1:3]:
                if (addr not in address_identified) and (addr in common_address_list):
                    address_identified[addr] = [f'$COMMONADDRESS{common_address_list.index(addr)}']
    return {
        'target_address':target_address,
        'address_identified':address_identified
        }

    
        