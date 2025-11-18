import os
import pandas
from tqdm import tqdm
from pocshift.solidityParser.hash_parser import parseString

def modify_pocs(input_dir, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    for project in os.listdir(input_dir):
        temp_output_dir = os.path.join(output_dir, project)
        os.makedirs(temp_output_dir, exist_ok=True)
        for file in os.listdir(os.path.join(input_dir, project)):
            content = open(os.path.join(input_dir, project, file), 'r').read()
            parse_result = parseString(content)
            for c in parse_result['contracts'][-1::-1]:
                if c['name'] == 'ContractTest':
                    for f in c['functions']:
                        if f['name'] == 'test':
                            end = int(f['loc']['end'].split(':')[0])
                            content_list = content.split('\n')
                            content = content_list[:end-2] + content_list[end-1:]
                            with open(os.path.join(temp_output_dir, file), 'w') as f:
                                f.write('\n'.join(content))
                            break
                    break

                      
def extract_successful_poc(input_dir, input_file, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    poc_dir = os.path.join(output_dir, 'poc')
    trace_dir = os.path.join(output_dir, 'trace')
    os.makedirs(poc_dir, exist_ok=True)
    os.makedirs(trace_dir, exist_ok=True)
    df = pandas.read_csv(input_file)
    output = {}
    for _,row in df.iterrows():
        if '[PASS]' in row['result']:
            if row['template'] not in output:
                output[row['template']] = 0
            output[row['template']] += 1
            if os.path.exists(os.path.join(input_dir,row['template'],row['address']+'.sol')):
                poc = open(os.path.join(input_dir,row['template'],row['address']+'.sol'), 'r').read()
                os.makedirs(os.path.join(poc_dir, row['template']),exist_ok=True)
                with open(os.path.join(poc_dir, row['template'],row['address']+'.sol'), 'w') as f:
                    f.write(poc)
            os.makedirs(os.path.join(trace_dir, row['template']),exist_ok=True)
            with open(os.path.join(trace_dir, row['template'],row['address']+'.txt'), 'w') as f:
                f.write(row['result'])
    df_count = df.groupby('template').size().reset_index(name='count')
    df2 = pandas.DataFrame(output.items(), columns=['template','success_count'])
    df2 = df_count.merge(df2, on='template', how='left')
    df2 = df2.fillna(0)
    df2.to_csv(os.path.join(output_dir, 'test_oracle.csv'))                       
                        

def add_in_vulnerability_information(input_file, data_file, output_file):
    df = pandas.read_csv(input_file)
    data_df = pandas.read_csv(data_file)
    df.rename(columns={'template':'file_name'}, inplace=True)
    data_df = data_df[['file_name','address','type_x','type_y']]
    data_df['chain'] = data_df['address'].apply(lambda x: x.split('_')[1])
    data_df['address'] = data_df['address'].apply(lambda x: x.split('_')[0])
    df = df.merge(data_df, on=['file_name','address'], how='left')
    df['success'] = df['result'].apply(lambda x: 1 if '[PASS]' in x else 0)
    df = df[df['success'] == 1]
    df = df[['file_name','address','type_x','type_y']]
    df = df.drop_duplicates(subset=['file_name','address'])
    df.loc[df['file_name'] == 'Sheep_exp.sol', 'type_y'] = 'Price manipulation'
    df.to_csv(output_file)
    
    
def group_by_vulnerability_type(input_file, output_file):
    df = pandas.read_csv(input_file)
    df = df.groupby('type_y').size().reset_index(name='count')
    df.to_csv(output_file)
    
                  
                        
if __name__ == '__main__':
    # modify_pocs(
    #     './src/migration_result_test2', 
    #     './src/migration_result_test2_rq2'
    #     )
    # extract_successful_poc(
    #     './src/migration_result_test2_rq2',
    #     './migration_test_result2_rq2.csv',
    #     './evaluation/result/rq2'
    # )
    add_in_vulnerability_information(
        './migration_test_result2_rq2.csv',
        './clone_result/merged_result/inspection_list_filtered100.csv',
        './evaluation/result/rq2/migration_result_test2_rq2.csv'
    )
    group_by_vulnerability_type(
        './evaluation/result/rq2/migration_result_test2_rq2.csv',
        './evaluation/result/rq2/vulnerability_type_count.csv'
    )