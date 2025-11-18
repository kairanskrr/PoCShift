import os
import json
import pandas
from tqdm import tqdm
from pocshift.candidate_matching.candidate_matching import CandidateMatching



def run_matching(file_path):
    cm = CandidateMatching()
    df = pandas.read_csv(file_path)
    output = {}
    for _, row in tqdm(df.iterrows(), total=df.shape[0]):
        temp = row['address'].split('_')
        address = temp[0]
        chain = temp[1]
        result = cm.get_suitable_template(row['vulnerable_code'], address, chain)
        output[address] = result
    temp = {}
    for key in output:
        temp_temp = []
        for entry in output[key]:
            if isinstance(entry, dict):
                temp_temp.append(entry['hash'])
        temp[key] = temp_temp
    
    with open('./evaluation/result/rq2/output1.json', 'w') as f:
        json.dump(temp, f)
        
        
def check_with_result(tool_summary, cm_output, output_file):
    df = pandas.read_csv(tool_summary)
    data = json.load(open(cm_output, 'r'))
    output = {'file_name':[],'address':[],'chain':[],'tool':[],'hash':[]}
    
    for address in data:
        tool = ''
        file_name = ''
        chain = ''
        if df[df['address'] == address.lower()].shape[0] > 0:
            tool = df[df['address'] == address.lower()]['tool'].values[0]
            chain = df[df['address'] == address.lower()]['chain'].values[0]
            file_name = df[df['address'] == address.lower()]['file_name'].values[0]
        hash = data[address][0] if len(data[address]) > 0 else ''
        output['file_name'].append(file_name)
        output['chain'].append(chain)
        output['address'].append(address)
        output['tool'].append(tool)
        output['hash'].append(hash)
    output_df = pandas.DataFrame(output)
    output_df.to_csv(output_file,index=False)


if __name__ == '__main__':
    run_matching('./clone_result/merged_result/inspection_list_filtered100.csv')
    # check_with_result(
    #     './evaluation/result/rq1/tool_summary.csv',
    #     './evaluation/result/rq2/output.json',
    #     './evaluation/result/rq2/candidate_matching.csv'
    # )