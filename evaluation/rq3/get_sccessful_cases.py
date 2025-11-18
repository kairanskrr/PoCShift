import os
import pandas
from pocshift.databases.constants import *
from pocshift.databases.utils import *


def get_trace_log_for_successful_cases(output_dir):
    os.makedirs(output_dir, exist_ok=True)
    poc_dir = os.path.join(output_dir, 'poc')
    os.makedirs(poc_dir, exist_ok=True)
    trace_dir = os.path.join(output_dir, 'trace')
    os.makedirs(trace_dir, exist_ok=True)      
    
    db = establish_connection()
    output = list(db[MATCHING_COLLECTION].find({'status':1}))
    for entry in output:
        if entry['poc_file'] != 'NovaExchange_exp.sol':
            folder_name = entry['poc_file'].replace('.sol','')
            os.makedirs(os.path.join(poc_dir, folder_name), exist_ok=True)
            os.makedirs(os.path.join(trace_dir, folder_name), exist_ok=True)
            address = entry['address']
            chain = entry['chain']
            with open(os.path.join(trace_dir, folder_name, f'{address}_{chain}.txt'), 'w') as f:
                f.write(entry['log'])
            with open(os.path.join(poc_dir, folder_name, f'{address}_{chain}.sol'), 'w') as f:
                f.write(entry['poc'])
                

def merge_with_rq1_result():
    output = {'template':[],'address':[],'chain':[]}
    for project in os.listdir('./evaluation/result/rq3/successful_cases/trace'):
        for file in os.listdir(os.path.join('./evaluation/result/rq3/successful_cases/trace', project)):
            output['template'].append(project)
            output['address'].append(file.replace('.txt','').split('_')[0])
            output['chain'].append(file.replace('.txt','').split('_')[1])
    inspection_list = pandas.read_csv('./clone_result/merged_result/inspection_list.csv')
    inspection_list['address'] = inspection_list['address'].str.lower()
    for project in os.listdir('./evaluation/result/rq1/pocshift/trace'):
        if 'NovaExchange_exp.sol' in project:
            continue
        for file in os.listdir(os.path.join('./evaluation/result/rq1/pocshift/trace', project)):
            output['template'].append(project.replace('.sol',''))
            output['address'].append(file.replace('.txt',''))
            output['chain'].append('temp')
    df = pandas.read_csv('./evaluation/result/rq3/revised_migration_result.csv')
    df = df[df['project']!='NovaExchange_exp']
    for _, row in df.iterrows():
        output['template'].append(row['project'])
        output['address'].append(row['address'])
        output['chain'].append(row['chain'])
    output_df = pandas.DataFrame(output)
    output_df = output_df.drop_duplicates(subset=['template','address'],keep='first')
    # output_df.to_csv('./evaluation/result/rq3/matching_list.csv',index=False)
    print(output_df.shape[0])
    
    raw_df = pandas.read_csv('./data_collection/finalized_dataset.csv')
    raw_df = raw_df[['file_name','chain']]
    raw_df.columns = ['template','chain_original']
    raw_df['template'] = raw_df['template'].str.replace('.sol','')
    output_df = pandas.merge(output_df, raw_df, on=['template'], how='left')
    output_df = output_df.drop_duplicates(subset=['template','address'],keep='first')
    output_df.to_csv('./evaluation/result/rq3/matching_list1.csv',index=False)
    
    
def process_matching_list():
    df = pandas.read_csv('./evaluation/result/rq3/matching_list.csv')
    df['chain'] = df['chain'].str.lower()
    df['chain_original'] = df['chain_original'].str.lower()
    df['same_chain'] = df['chain'] == df['chain_original']
    df['cross'] = df['chain'] + '_' + df['chain_original']
    df.to_csv('./evaluation/result/rq3/matching_list_checked.csv',index=False)

     
if __name__ == '__main__':
    # get_trace_log_for_successful_cases('./evaluation/result/rq3/successful_cases')
    # merge_with_rq1_result()
    process_matching_list()