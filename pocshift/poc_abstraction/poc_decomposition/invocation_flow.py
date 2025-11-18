import os
import re
import subprocess
import traceback
from copy import deepcopy


class InvocationFlow:
    def __init__(self, file_path):
        
        # temp 
        poc_name = file_path.split('/')[-1].strip().replace('.sol','.txt')
        if os.path.exists(os.path.join('./tx_trace', poc_name)):
            with open(os.path.join('./tx_trace', poc_name), 'r') as f:
                self.raw_flow = f.read()
        else:
            self.raw_flow = self._obtain_invocation_flow(file_path)

    def _obtain_invocation_flow(self,file_path):
        try:
            command = ["forge", "test", "--contracts", os.path.join(file_path), '-vvvvv']
            result = subprocess.run(command, capture_output=True, text=True,timeout=3600)
            return result.stdout
        except Exception:
            traceback.print_exc()
            return None

    def _parse_invocation_line(self, line):
        if "console::log" in line:
            return None
        if "VM::" in line:
            keyword = line.split("VM::")[1].split("(")[0]
            params = line.split("(")[1].split(")")[0]
            return {
                "call_type": "vm",
                "keyword": keyword,
                "params": params,
                "children": []
            }   
        match = re.match(r'.*?(0x[a-fA-F0-9]{40})::(\w+)(?:\{value:\s*([\d]+)\})?\((.*?)\)(?: \[(\w+)\])?', line) # function call
        if match:
            if len(match.groups()) == 5:
                address, function_name, value, params, call_type = match.groups()   
            else:
                address, function_name, params, call_type = match.groups()
                value = None
            return {
                "address": address,
                "function_name": function_name,
                "params": params,
                "value": value,
                "call_type": call_type,
                "children": []
            }
        else:
            match = re.match(r'^\s*│.*?emit (\w+)\((.*?)\)', line) # event log
            if match:
                event_name, params = match.groups()
                return {
                    "event_name": event_name,
                    "params": params,
                    "call_type": "event",
                    "children": []
                }
            else:
                match = re.search(r"new\s*(\w+)@(0x[0-9a-fA-F]{40})", line)
                if match:
                    contract_name, contract_address = match.groups()
                    return {
                        "contract_address": contract_address,
                        "contract_name": contract_name,
                        "call_type": "new_contract",
                        'children': []
                    }
        return None

    def parse_invocation_flow(self, flow_lines):
        stack = []
        current_depth = 0
        contract_address_memo = {}
        matches = set(re.findall(r'.*?(\w+):\s*\[(0x[a-fA-F0-9]{40})\]',''.join(flow_lines)))
        for match in matches:
            contract_name, address = match
            if contract_name not in contract_address_memo:
                contract_address_memo[contract_name] = address
        for line in flow_lines:
            for i in contract_address_memo:
                if (i in line) and ('→ new ' not in line):
                    line = line.replace(i, contract_address_memo[i])
                    break
            depth = line.count('│') + line.count('├─') + line.count('└─')
            if depth < current_depth:
                temp = []
                for i in range(len(stack)-1,-1,-1):
                    if stack[i]['depth'] > depth:
                        temp.append(stack[i])
                    else:
                        break
                stack = stack[:i+1]
                temp = deepcopy(temp[::-1])
                if len(stack) == 0:
                    stack.extend(temp)
                else:
                    stack[-1]["children"].extend(temp)
            node = self._parse_invocation_line(line)
            if node:
                node['depth'] = depth
                current_depth = depth
                stack.append(node)
                if node['call_type'] == 'new_contract':
                    contract_address_memo[f"{node['contract_name']}::"] = f"{node['contract_address']}::"
        return stack


    def locate_start_pointer(self, lines):
        for i in range(len(lines)):
            match = re.match(r'^\s*\[\s*(\d+)\s*\]\s*(\w+)::(\w+)\s*\(\s*\)\s*$', lines[i])
            if match:
                _, _, function_name = match.groups()
                if function_name.startswith('test'):
                    return i+1
        return -1

    def locate_end_pointer(self, lines):
        for i in range(len(lines)-1,-1,-1):
            if '└─' in lines[i]:
                return i+1
        return -1

    def parse(self):
        content_lines = self.raw_flow.split('\n')
        
        if '[PASS]' in self.raw_flow:
            start_line = self.locate_start_pointer(content_lines)
            if start_line == -1:
                return None
            end_line = self.locate_end_pointer(content_lines)
            if end_line == -1:
                return None
            return self.parse_invocation_flow(content_lines[start_line:end_line])
        return None
