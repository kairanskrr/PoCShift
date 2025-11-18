import os
import json
import pandas



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
    df2.to_csv(os.path.join(output_dir, 'template_count.csv'))
    

def analyze_evaluation_dataset(input_file):
    df = pandas.read_csv(input_file)
    df.groupby('type_y').size().reset_index(name='count').to_csv('./evaluation/result/rq1/type_count.csv')


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
    
    
def analyze_ityfuzz(input_dir, input_file,data_file,output_dir,output_file):
    os.makedirs(output_dir, exist_ok=True)
    data = json.load(open(input_file, 'r'))
    df = pandas.read_csv(data_file)
    output = {'file_name':[],'address':[],'chain':[]}
    for i in data:
        temp = i.replace('.txt','').rsplit('_',2)
        template = temp[0]+'.sol'
        address = temp[1]
        chain = temp[2]
        content = open(os.path.join(input_dir,i),'r').read()
        with open(os.path.join(output_dir, i), 'w') as f:
            f.write(content)
        output['file_name'].append(template)
        output['address'].append(address)
        output['chain'].append(chain)
    output_df = pandas.DataFrame(output)
    df['address'] = df['address'].apply(lambda x: x.split('_')[0])
    df = df[['file_name','address','type_x','type_y','vulnerable_code']]
    output_df = output_df.merge(df, on=['file_name','address'], how='left')
    output_df.to_csv(output_file)
    

def group_itfuzz_by_vulnerability_type(input_file, output_file):
    df = pandas.read_csv(input_file)
    df = df.groupby('type_y').size().reset_index(name='count')
    df.to_csv(output_file)
    

def check_result(pocshift,ityfuzz,output):
    df1 = pandas.read_csv(pocshift)
    df2 = pandas.read_csv(ityfuzz)
    df1 = df1[['address']]
    df2 = df2[['address']]
    df_pocshift_only = df1.merge(df2, on='address', how='left')
    df_pocshift_only = df_pocshift_only[df_pocshift_only['address'].isnull()]
    df_ityfuzz_only = df2.merge(df1, on='address', how='left')
    df_ityfuzz_only = df_ityfuzz_only[df_ityfuzz_only['address'].isnull()]
    df_pocshift_only.to_csv(output+'/pocshift_only.csv')
    df_ityfuzz_only.to_csv(output+'/ityfuzz_only.csv')
    
    
def get_sample_for_manual_inspection(pocshift, ityfuzz, inspection, output_file):
    df1 = pandas.read_csv(pocshift)
    df2 = pandas.read_csv(ityfuzz)
    data = pandas.read_csv(inspection)
    df1 = df1[['file_name', 'address']]
    df2 = df2[['file_name', 'address']]
    df1['tool'] = 'pocshift'
    df2['tool'] = 'ityfuzz'
    df = pandas.concat([df1,df2], ignore_index=True)
    data['chain'] = data['address'].apply(lambda x: x.split('_')[1])
    data['address'] = data['address'].apply(lambda x: x.split('_')[0])
    data = data[['file_name','address','chain','vulnerable_code','taxonomy_mapping','type_x','type_y']]
    data = data.merge(df, on=['file_name', 'address'], how='left')
    data['tool'] = data['tool'].fillna('manual')
    data.to_csv('./evaluation/result/rq1/tool_summary.csv')
    data = data[data['tool'] == 'manual']
    output = {'file_name':[],'address':[],'chain':[],'vulnerable_code':[],'type_x':[],'type_y':[],'taxonomy_mapping':[]}
    for file_name in data['file_name'].unique():
        temp = data[data['file_name'] == file_name]
        if temp.shape[0] > 50:
            temp = temp.sample(n=50)
        output['file_name'].extend(temp['file_name'].tolist())
        output['address'].extend(temp['address'].str.split('_').str[0].tolist())
        output['chain'].extend(temp['chain'].tolist())
        output['vulnerable_code'].extend(temp['vulnerable_code'].tolist())
        output['type_x'].extend(temp['type_x'].tolist())
        output['type_y'].extend(temp['type_y'].tolist())
        output['taxonomy_mapping'].extend(temp['taxonomy_mapping'].tolist())
    pandas.DataFrame(output).to_csv(output_file) 


def extract_data_for_manual_inspection(tool_summary,output_file):
    df = pandas.read_csv(tool_summary)
    output = {'file_name':[],'address':[],'chain':[],'vulnerable_code':[],'type_x':[],'type_y':[],'taxonomy_mapping':[],'tool':[]}
    for vuln_type in df['type_y'].unique():
        temp = df[df['type_y'] == vuln_type]
        for clone_type in temp['type_x'].unique():
            temp_temp = temp[temp['type_x'] == clone_type]
            if temp_temp.shape[0] > 30:
                temp_temp = temp_temp.sample(n=30)
            output['file_name'].extend(temp_temp['file_name'].tolist())
            output['address'].extend(temp_temp['address'].str.split('_').str[0].tolist())
            output['chain'].extend(temp_temp['chain'].tolist())
            output['vulnerable_code'].extend(temp_temp['vulnerable_code'].tolist())
            output['type_x'].extend(temp_temp['type_x'].tolist())
            output['type_y'].extend(temp_temp['type_y'].tolist())
            output['taxonomy_mapping'].extend(temp_temp['taxonomy_mapping'].tolist())
            output['tool'].extend(temp_temp['tool'].tolist())
    print(len(output['file_name']))
    df = pandas.DataFrame(output)
    # TODO: count number of pocshift and ityfuzz
    df.to_csv(output_file.replace('.csv','_all.csv'), index=False)
    

if __name__ == '__main__':
    # extract_successful_poc(
    #     './src/migration_result_test2',
    #     './migration_test_result2.csv',
    #     './evaluation/result/rq1/pocshift'
    # )
    # analyze_evaluation_dataset('./clone_result/merged_result/inspection_list_filtered100.csv')
    # add_in_vulnerability_information(
    #     './migration_test_result2.csv',
    #     './clone_result/merged_result/inspection_list_filtered100.csv',
    #     './evaluation/result/rq1/pocshift/migration_result_test2.csv'
    # )
    # group_by_vulnerability_type(
    #     './evaluation/result/rq1/pocshift/migration_result_test2.csv',
    #     './evaluation/result/rq1/pocshift/vulnerability_type_count.csv'
    # )
    # analyze_ityfuzz(
    #     './SOTA/ItyFuzz/eval_test',
    #     './SOTA/ItyFuzz/output_test.json',
    #     './clone_result/merged_result/inspection_list_filtered100.csv',
    #     './evaluation/result/rq1/ityfuzz/trace',
    #     './evaluation/result/rq1/ityfuzz/ityfuzz_result.csv'
    # )
    # group_itfuzz_by_vulnerability_type(
    #     './evaluation/result/rq1/ityfuzz/ityfuzz_result.csv',
    #     './evaluation/result/rq1/ityfuzz/vulnerability_type_count.csv'
    # )
    # check_result(
    #     './evaluation/result/rq1/pocshift/migration_result_test2.csv',
    #     './evaluation/result/rq1/ityfuzz/ityfuzz_result.csv',
    #     './evaluation/result/rq1'
    # )
    # get_sample_for_manual_inspection(
    #     './evaluation/result/rq1/pocshift/migration_result_test2.csv',
    #     './evaluation/result/rq1/ityfuzz/ityfuzz_result.csv',
    #     './clone_result/merged_result/inspection_list_filtered100.csv',
    #     './evaluation/result/rq1/manual_inspection_sample.csv'
    # )
    extract_data_for_manual_inspection(
        './evaluation/result/rq1/tool_summary.csv',
        './evaluation/result/rq1/manual_inspection_sample.csv'
    )