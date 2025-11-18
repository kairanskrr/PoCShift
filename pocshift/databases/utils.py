import os
import re
import pymongo
import traceback
from copy import deepcopy
import hashlib
from dotenv import load_dotenv
from pocshift.databases.constants import *
load_dotenv()

def establish_connection():
    return pymongo.MongoClient( os.environ.get('MONGO_URI') )[MONGO_DB]

db = establish_connection()


# parse file
def stringClean(string:str):
    return string.replace("'","").replace('"','').replace(' ','').replace('\n','')

def getImports(file_path):
    imports_temp = {}
    lib_list = []
    f = open(file_path, 'r', encoding='utf-8')
    lines = f.readlines()
    for line in lines:
        if re.match(r'^import', line):
            i = line.replace(';','').replace('"','').replace("'","").replace('\n','')
            import_path = i.replace('import ', '').strip()
            if 'from' in i:
                import_path = i.split('from')[1].strip()
            if ('src/' in import_path):
                continue
                
            lib_name = ''
            source = ''
            if ('@' in import_path): 
                lib_name = '@'+'/'.join(i.split('@')[-1].split('/')[:2])
                source = 'npm'
            elif 'https://github.com' in import_path:
                lib_name = 'https://api.github.com/repos' + '/'.join(i.split('https://github.com')[-1].split('/',)[:3])+'/tags'
                source = 'github'
            elif ('./' not in import_path) and ('/' in import_path):
                lib_name = import_path.split('/')[0].replace('.sol','')
                source = 'npm'

            if lib_name != '':
                import_contract_name = import_path.split('/')[-1].replace('.sol','')
                imports_temp[import_contract_name] = {'contract_name':import_contract_name,'path': import_path, 'lib_name': lib_name, 'index':-1, 'source':source}
                if lib_name not in lib_list:
                    lib_list.append(lib_name)
    return imports_temp,lib_list

def checkImport(import_statement):
    lib_name = ''
    import_contract_name = ''
    if ('@' in import_statement): 
        lib_name = '@'+'/'.join(import_statement.split('@')[-1].split('/')[:2])
    elif ('./' not in import_statement) and ('/' in import_statement):
        lib_name = import_statement.split('/')[0].replace('.sol','')
    if lib_name != '':
        import_contract_name = import_statement.split('/')[-1].replace('.sol','')
        return True, import_contract_name, {'path': import_statement, 'lib_name': lib_name, 'contract_index':-1}
    return False, import_contract_name, {}

def checkContractInDatabase(address, hash):
    collection = db[CONTRACT_COLLECTION]
    if collection.count_documents({'hash':hash}) > 0:
        db_entry = collection.find({'hash':hash}).next()
        if address not in db_entry['address']:
            contract_count_incr()    
            collection.update_many({"hash": hash},{ "$addToSet": {"address":address} })
        return 0
    return contract_count_incr()


def checkSUBContractInDatabase(hash, parent_index):
    try:
        collection = db[SUBCONTRACT_COLLECTION]
        if collection.count_documents({'hash':hash}) > 0:
            entry = collection.find({'hash':hash}).next()
            parent_index_list = list(entry['parent_index'])
            collection.update_many({"hash": hash},{ "$addToSet": {"parent_index":parent_index} })
            return True, entry['index'], parent_index_list
        else:
            return False, subcontract_count_incr(), []
    except Exception:
        traceback.print_exc()
        
def saveStatementToDatabase(statement, parent_index):
    # try:
        collection = db[STATEMENT_COLLECTION]
        if collection.count_documents({'hash':statement['hash']}) == 0:
            statement_index = statement_count_incr()
            statement['parent_index'] = [parent_index]
            statement['origin'] = parent_index
            statement['index'] = statement_index
            collection.insert_one(statement)
        else:
            entry = collection.find({'hash':statement['hash']}).next()
            collection.update_many({'hash':statement['hash']},{ "$addToSet": {"parent_index":parent_index} })
            statement_index = entry['index']
        return statement_index
    # except Exception as e:
    #     print(e)
    #     return -1

    
def checkGraphInDatabase(graph, graph_hash, parent_index, parent_parent_index):
    collection = db[GRAPH_COLLECTION]
    if collection.count_documents({'hash':graph_hash}) == 0:
        graph_index = graph_count_incr()
        # saveGraphToDatabase(graph.graph, graph_index)
        collection.insert_one({'hash':graph_hash, 'index':graph_index, 'parent_index':[parent_index], 'parent_parent_index':[parent_parent_index]})
    else:
        entry = collection.find({'hash':graph_hash}).next()
        collection.update_many({'hash':graph_hash},{ "$addToSet": {"parent_index":parent_index, "parent_parent_index":parent_parent_index} })
        graph_index = entry['index']
    return graph_index

def saveFunctionToDatabase(function, parent_index):
        # try:
            function = deepcopy(function)
            collection = db[FUNCTION_COLLECTION]
            if collection.count_documents({'hash':function['hash']}) == 0:
                function_index = function_count_incr()
                statement_list = []
                statement_cached = {}
                for statement in function['statements']:
                        statement_index = saveStatementToDatabase(statement, f'f{function_index}')
                        statement_list.append(statement_index)
                        statement_cached[statement['hash']] = statement                        
                # statement_list = [saveStatementToDatabase(statement, f'f{function_index}') for statement in function['statements']]  
                function['parent_index'] = [parent_index]
                function['origin'] = parent_index
                function['index'] = function_index
                function['statements'] = statement_list
                if function['has_body']:
                    function['graph_index'] = [checkGraphInDatabase(function['dfg'], function['dfg_hash'], f'f{function_index}', parent_index)] 
                else:
                    function['graph_index'] = []
                del function['dfg']
                del function['dfg_hash']
                collection.insert_one(function)
            else:
                entry = collection.find({'hash':function['hash']}).next()
                function_index = entry['index']
                if function['has_body']:
                    graph_index = checkGraphInDatabase(function['dfg'], function['dfg_hash'], f'f{function_index}',parent_index)
                    collection.update_many({'hash':function['hash']},{ "$addToSet": {"parent_index":parent_index, "graph_index":graph_index} })
                else:
                    collection.update_many({'hash':function['hash']},{ "$addToSet": {"parent_index":parent_index} })
                statement_cached = {}
                for statement in function['statements']:
                    statement_cached[statement['hash']] = statement    
                      
            return function_index,statement_cached
        # except Exception as e:
        #     print(e)
        #     return -1


def saveSUBContractToDatabase(contract, parent_index):
        # try:
            in_db, contract_index,_ = checkSUBContractInDatabase(contract['hash'], parent_index)
            if not in_db:
                collection = db[SUBCONTRACT_COLLECTION]
                function_list = []
                statements = {}
                for function in contract['functions']:
                    function_index, statement_cached = saveFunctionToDatabase(contract['functions'][function], f's{contract_index}')
                    function_list.append(function_index)
                    statements.update(statement_cached)
                # function_list = [saveFunctionToDatabase(contract['functions'][function], f's{contract_index}') for function in contract['functions']]  
                contract['parent_index'] = [parent_index]
                contract['origin'] = parent_index
                contract['index'] = contract_index
                contract['functions'] = function_list
                collection.insert_one(contract)
                return contract_index, statements
            statements = {}
            for function in contract['functions']:
                for statement in contract['functions'][function]['statements']:
                    statements[statement['hash']] = statement
            return contract_index, statements
        # except Exception as e:
        #     traceback.print_exc()
        #     return -1

def saveContractToDatabase(address, contract_name, contract_hash, contract_index, contract_list, function_list, statement_dict):
        try:
            # contract_index = checkContractInDatabase(address, contract_hash)
            # if contract_index == 0:
            #     return
            collection = db[CONTRACT_COLLECTION]
            collection.create_index('hash', unique=True)
            entry = {
                "address": [address], 
                "name":contract_name, 
                "hash":contract_hash, 
                "contract_list": contract_list,
                "function_list": function_list,  
                "statement_dict": statement_dict,
                "index": contract_index, 
                "status": 0
                }
            collection.insert_one(entry)
        except Exception as e:
            traceback.print_exc()

# update data summary in database
def update_tracker(name):
    tracker = db[TRACKER_COLLECTION]
    return tracker.find_one_and_update({'name':name},{ "$inc": {"count":1} })['count']

def contract_count_incr():
    return update_tracker(CONTRACT_COLLECTION)

def subcontract_count_incr():
    return update_tracker(SUBCONTRACT_COLLECTION)

def function_count_incr():
    return update_tracker(FUNCTION_COLLECTION)

def statement_count_incr():
    return update_tracker(STATEMENT_COLLECTION)

def graph_count_incr():
    return update_tracker(GRAPH_COLLECTION)

