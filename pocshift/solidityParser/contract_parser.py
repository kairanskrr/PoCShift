import re
import antlr4
from copy import deepcopy
from pocshift.candidate_matching.utils import hashString
from pocshift.candidate_matching.graph import CodePropertyGraph
from pocshift.solidityParser.antlrGenerated.SolidityLexer import SolidityLexer
from pocshift.solidityParser.antlrGenerated.SolidityParser import SolidityParser
from pocshift.solidityParser.antlrGenerated.SolidityListener import SolidityListener


class ContractParser(SolidityListener):
    def __init__(self, token_stream, vuln_code=[]):
        ### Global variables
        self.token_stream = token_stream
        self.tokens = token_stream.tokens
        self.raw_text = token_stream.getText()
        self.contracts = {}
        self.functions = {}
        self.function_global = {}
        ### Contract variables
        self.current_contract = None
        self.isMainContract = False
        self.last_line_of_import = -1
        self.first_line_of_state_variables = -1
        self.last_line_of_state_variables = -1
        self.first_line_of_function = -1
        self.global_state_variables = []
        self.first_contract = True
        self.imports = []
        self.compiler_version = ''
        ### Function variables
        self.current_function = None
        self.function_variables = set()        
        self.statements = []
        self.relations = []
        ### Vulnerable point
        self.vuln_code = [v.replace(' ','') for v in vuln_code]
        self.vuln_code.extend([v.strip(';') for v in self.vuln_code])
        self.vuln_code_statements = []
    
        
    ### Utils
    def _get_normalized_text(self, start_token_index, stop_token_index):
        normalized_output = ''
        original_output = ''
        for i in range(start_token_index, stop_token_index + 1):
            token = self.tokens[i]
            content = token.text
            token_type = token.type
            if token.channel == 0:
                if token_type == SolidityLexer.StringLiteral:
                    normalized_output += 'STRING'
                    original_output += f'{content}'
                elif token_type == SolidityLexer.DecimalNumber:
                    normalized_output += 'NUMBER'
                    original_output += f'{content}'
                elif token_type == SolidityLexer.HexNumber:
                    normalized_output += 'HEX'
                    original_output += f'{content}'
                elif token_type == SolidityLexer.BooleanLiteral:
                    normalized_output += 'BOOL'
                    original_output += f'{content}'
                elif (token_type == SolidityLexer.Identifier) and (content not in ['msg', 'sender', 'max']):
                    normalized_output += 'VAR'
                    original_output += f'{content}'
                else:
                    normalized_output += f'{content}'
                    original_output += f'{content}'
            else:
                original_output += f'{content}'
        return normalized_output, original_output
     
    def _collect_identifiers(self, ctx, variable_names):
        if isinstance(ctx, SolidityParser.PrimaryExpressionContext):
            if ctx.identifier():
                var_name = ctx.identifier().getText()
                variable_names.append(var_name)
        elif isinstance(ctx, SolidityParser.ExpressionContext):
            for child in ctx.getChildren():
                if isinstance(child, SolidityParser.FunctionCallArgumentsContext):
                    if child.expressionList():
                        for var_name in child.expressionList().expression():
                            variable_names.append(var_name.getText())
        else:
            if isinstance(ctx,SolidityParser.ExpressionContext):
                for child in ctx.getChildren():
                    self._collect_identifiers(child, variable_names)    
    
    def _reset_contract_variables(self):
        self.current_contract = None
        self.isMainContract = False
        self.last_line_of_import = -1
        self.first_line_of_state_variables = -1
        self.last_line_of_state_variables = -1
        self.first_line_of_function = -1
        self.global_state_variables = []
        self.first_contract = True
        self.imports = []
        self.compiler_version = ''
        
    ### For hashing
    def _compute_expression_hash(self, ctx:SolidityParser.ExpressionContext):
        if ctx is None:
            return {},[]
        start_token_index = ctx.start.tokenIndex
        stop_token_index = ctx.stop.tokenIndex
        normalized_output, original_output = self._get_normalized_text(start_token_index, stop_token_index)
        expr_hash = hashString(normalized_output)
        expr_id = expr_hash[:6]
        variable_names = []
        self._collect_identifiers(ctx, variable_names)
        expr_info = {
            'id': expr_id,
            'type': 'expression',
            'hash': expr_hash,
            'normalized_code': normalized_output,
            'original_code': original_output,
            'variables': variable_names,
            'start_line': ctx.start.line,
            'end_line': ctx.stop.line,
        }
        self.statements.append(expr_info)
        return expr_info,[]
    
    def _compute_block_hash(self, block_ctx_input, variable_definitions):
        relations = []
        block_statements = []
        if isinstance(block_ctx_input, list):
            for block_ctx in block_ctx_input:
                if block_ctx and block_ctx.statement():
                    statements = block_ctx.statement()
                    for statement in statements:
                        stmt_info, stmt_relations = self._compute_statement_hash(statement, variable_definitions)
                        block_statements.extend(stmt_info)
                        relations.extend(stmt_relations)

                    # Record control flow relations between statements in the block
                    for i in range(len(block_statements) - 1):
                        current_stmt = block_statements[i]
                        next_stmt = block_statements[i + 1]
                        relations.append((current_stmt['id'], next_stmt['id'], 'control', None))
        else:
            statements = block_ctx_input.statement()
            for statement in statements:
                stmt_info, stmt_relations = self._compute_statement_hash(statement, variable_definitions)
                block_statements.extend(stmt_info)
                relations.extend(stmt_relations)

            # Record control flow relations between statements in the block
            for i in range(len(block_statements) - 1):
                current_stmt = block_statements[i]
                next_stmt = block_statements[i + 1]
                relations.append((current_stmt['id'], next_stmt['id'], 'control', None))

        return block_statements, relations
    
    
    def _check_woth_vuln_code(self, stmt_info):
        if stmt_info['original_code'] in self.vuln_code:
            self.vuln_code_statements.append(stmt_info)
 
    def _compute_statement_hash(self, ctx:SolidityParser.StatementContext, variable_definitions):
        relations = []
        stmt_info = []
        
        if ctx is None:
            return stmt_info, relations
        
        def _process_statement_info(stmt_ctx:SolidityParser.StatementContext, variable_definitions=variable_definitions):
            if stmt_ctx is None:
                return {},[]
            if isinstance(stmt_ctx, SolidityParser.SimpleStatementContext):
                relations = []
                stmt_info = {}
                if stmt_ctx.variableDeclarationStatement():
                    var_decl_ctx = stmt_ctx.variableDeclarationStatement()
                    # Process variable declaration statement
                    start_token_index = var_decl_ctx.start.tokenIndex
                    stop_token_index = var_decl_ctx.stop.tokenIndex
                    normalized_output, original_output = self._get_normalized_text(start_token_index, stop_token_index)
                    stmt_hash = hashString(normalized_output)
                    stmt_id = stmt_hash[:6]
                    # Extract variable names
                    variable_names = []
                    var_decl = var_decl_ctx.variableDeclaration()
                    if var_decl is None:
                        var_decl = var_decl_ctx.variableDeclarationList().variableDeclaration(0) if var_decl_ctx.variableDeclarationList() else None   
                    if (var_decl is not None) and (var_decl.identifier()):             
                        var_name = var_decl.identifier().getText()
                        variable_names.append(var_name)
                        variable_definitions[var_name] = stmt_id  # Record definition
                    stmt_info = {
                        'id': stmt_id,
                        'type': 'variable_declaration',
                        'hash': stmt_hash,
                        'normalized_code': normalized_output,
                        'original_code': original_output,
                        'variables': variable_names,
                        'start_line': var_decl_ctx.start.line,
                        'end_line': var_decl_ctx.stop.line,
                    }
                    self._check_woth_vuln_code(stmt_info)
                elif stmt_ctx.expressionStatement():
                    expr_stmt_ctx = stmt_ctx.expressionStatement()
                    expression_ctx = expr_stmt_ctx.expression()
                    expr_info,expr_relations = self._compute_expression_hash(expression_ctx)
                    relations.extend(expr_relations)
                    stmt_info = {
                        'id': expr_info['id'],
                        'type': 'expression_statement',
                        'hash': expr_info['hash'],
                        'normalized_code': expr_info['normalized_code'],
                        'original_code': expr_info['original_code'],
                        'variables': expr_info['variables'],
                        'start_line': expr_stmt_ctx.start.line,
                        'end_line': expr_stmt_ctx.stop.line,
                    }
                    self._check_woth_vuln_code(stmt_info)
                    # Record data flow relations
                    for var_name in expr_info['variables']:
                        if var_name in variable_definitions:
                            def_stmt_id = variable_definitions[var_name]
                            relations.append((def_stmt_id, stmt_info['id'], 'data', var_name))
            elif hasattr(stmt_ctx, 'block') and stmt_ctx.block():
                stmt_info, relations = self._compute_block_hash(stmt_ctx.block(), variable_definitions)
            else:
                start_token_index = stmt_ctx.start.tokenIndex
                stop_token_index = stmt_ctx.stop.tokenIndex
                normalized_output, original_output = self._get_normalized_text(start_token_index, stop_token_index)
                stmt_hash = hashString(normalized_output)
                stmt_id = stmt_hash[:6]
                stmt_info = {
                    'id': stmt_id,
                    'type': 'statement',
                    'hash': stmt_hash,
                    'normalized_code': normalized_output,
                    'original_code': original_output,
                    'start_line': stmt_ctx.start.line,
                    'end_line': stmt_ctx.stop.line,
                }
                relations = []
                self._check_woth_vuln_code(stmt_info)
            return stmt_info, relations        
        if isinstance(ctx, SolidityParser.SimpleStatementContext):
            stmt_ctx = ctx
            if stmt_ctx.variableDeclarationStatement():
                var_decl_ctx = stmt_ctx.variableDeclarationStatement()
                # Process variable declaration statement
                start_token_index = var_decl_ctx.start.tokenIndex
                stop_token_index = var_decl_ctx.stop.tokenIndex
                normalized_output, original_output = self._get_normalized_text(start_token_index, stop_token_index)
                stmt_hash = hashString(normalized_output)
                stmt_id = stmt_hash[:6]
                # Extract variable names
                variable_names = []
                var_decl = var_decl_ctx.variableDeclaration()
                if var_decl is None:
                    var_decl = var_decl_ctx.variableDeclarationList().variableDeclaration(0) if var_decl_ctx.variableDeclarationList() else None   
                if (var_decl is not None) and (var_decl.identifier()):             
                    var_name = var_decl.identifier().getText()
                    variable_names.append(var_name)
                    variable_definitions[var_name] = stmt_id  # Record definition
                stmt_info = {
                    'id': stmt_id,
                    'type': 'variable_declaration',
                    'hash': stmt_hash,
                    'normalized_code': normalized_output,
                    'original_code': original_output,
                    'variables': variable_names,
                    'start_line': var_decl_ctx.start.line,
                    'end_line': var_decl_ctx.stop.line,
                }
                self._check_woth_vuln_code(stmt_info)
            elif stmt_ctx.expressionStatement():
                expr_stmt_ctx = stmt_ctx.expressionStatement()
                expression_ctx = expr_stmt_ctx.expression()
                expr_info,expr_relations = self._compute_expression_hash(expression_ctx)
                relations.extend(expr_relations)
                stmt_info = {
                    'id': expr_info['id'],
                    'type': 'expression_statement',
                    'hash': expr_info['hash'],
                    'normalized_code': expr_info['normalized_code'],
                    'original_code': expr_info['original_code'],
                    'variables': expr_info['variables'],
                    'start_line': expr_stmt_ctx.start.line,
                    'end_line': expr_stmt_ctx.stop.line,
                }
                self._check_woth_vuln_code(stmt_info)
                # Record data flow relations
                for var_name in expr_info['variables']:
                    if var_name in variable_definitions:
                        def_stmt_id = variable_definitions[var_name]
                        relations.append((def_stmt_id, stmt_info['id'], 'data', var_name))
        elif ctx.ifStatement():
            stmt_ctx = ctx.ifStatement()
            condition_ctx = stmt_ctx.expression()
            condition_info = self._compute_expression_hash(condition_ctx)     
            normalized_output, original_output = self._get_normalized_text(condition_ctx.start.tokenIndex, condition_ctx.stop.tokenIndex)       
            normalized_output = f'if({normalized_output})'
            original_output = f'if ({original_output})'
            stmt_hash = hashString(normalized_output)
            stmt_id = stmt_hash[:6]
            # stmt_info,_ = _process_statement_info(stmt_ctx)
            stmt_info = {
                'id': stmt_id,
                'type': 'if',
                'hash': stmt_hash,
                'normalized_code': normalized_output,
                'original_code': original_output,
                'start_line': stmt_ctx.start.line,
                'end_line': stmt_ctx.stop.line,
            }
            self._check_woth_vuln_code(stmt_info)
            stmt_info['condition'] = condition_info

            # Process block
            if_block_output = []
            if stmt_ctx.block():
                for block in stmt_ctx.block():
                    block_info, block_relations = self._compute_block_hash(block, variable_definitions)
                    if_block_output.extend(block_info)
                    relations.extend(block_relations)
                    # Record control flow relation
                    for bb in block_info:
                        relations.append((stmt_info['id'], bb['id'], 'control', None))
            stmt_info['block'] = if_block_output
            
            # Process 'then' statement
            then_stmt_info = []
            if stmt_ctx.statement():
                then_stmt_ctx = stmt_ctx.statement(0)
                then_stmt_info, then_relations = _process_statement_info(then_stmt_ctx,variable_definitions)
                stmt_info['then'] = then_stmt_info
                relations.extend(then_relations)
                # Record control flow relation
                relations.append((stmt_info['id'], then_stmt_info['id'], 'control', None))
        
            stmt_info = [stmt_info]
            stmt_info.extend(if_block_output)
            if isinstance(then_stmt_info, list):
                stmt_info.extend(then_stmt_info)
            else:
                stmt_info.append(then_stmt_info)
        elif ctx.forStatement():
            stmt_ctx = ctx.forStatement()
            init_stmt_ctx = stmt_ctx.simpleStatement()
            init_stmt_info, init_stmt_relations = _process_statement_info(init_stmt_ctx, variable_definitions)
            condition_ctx = stmt_ctx.expression()
            condition_info,condition_relations = self._compute_expression_hash(condition_ctx)
            condition_stmt_ctx = stmt_ctx.expressionStatement()
            condition_stmt_info, condition_stmt_relations = _process_statement_info(condition_stmt_ctx, variable_definitions)
            
            if condition_ctx:
                normalized_output, original_output = self._get_normalized_text(stmt_ctx.start.tokenIndex, condition_ctx.stop.tokenIndex)
            elif condition_stmt_ctx:
                normalized_output, original_output = self._get_normalized_text(stmt_ctx.start.tokenIndex, condition_stmt_ctx.stop.tokenIndex)
            else:
                normalized_output, original_output = self._get_normalized_text(stmt_ctx.start.tokenIndex, stmt_ctx.stop.tokenIndex)
            normalized_output = f'{normalized_output})'
            original_output = f'{original_output})'
            stmt_hash = hashString(normalized_output)
            stmt_id = stmt_hash[:6]
            
            stmt_info = {
                'id': stmt_id,
                'type': 'for',
                'hash': stmt_hash,
                'normalized_code': normalized_output,
                'original_code': original_output,
                'start_line': stmt_ctx.start.line,
                'end_line': stmt_ctx.stop.line,
                'init': init_stmt_info,
                'condition': condition_info,
                'iteration': condition_stmt_info,
                'body': None,
            }
            
            self._check_woth_vuln_code(stmt_info)
            relations.extend(condition_relations)
            relations.extend(condition_stmt_relations)
            relations.extend(init_stmt_relations)
            
            
            body_info = []
            if stmt_ctx.statement():
                body_ctx = stmt_ctx.statement()
                body_info, body_relations = _process_statement_info(body_ctx, variable_definitions)
                stmt_info['body'] = body_info
                relations.extend(body_relations)           
                if not isinstance(body_info, list):
                    body_info = [body_info]

            stmt_info = [stmt_info]
            if init_stmt_info:
                stmt_info.append(init_stmt_info)
            if condition_stmt_info:
                stmt_info.append(condition_stmt_info)
            if condition_info:
                stmt_info.extend(body_info)

            # Record control flow relations
            # From init to condition
            if init_stmt_info and condition_info:
                relations.append((init_stmt_info['id'], condition_info['id'], 'control', None))
            # From condition to body
            if condition_info and body_info:
                for bb in body_info:
                    relations.append((condition_info['id'], bb['id'], 'control', None))
                # relations.append((condition_expr_info['id'], body_stmt_info['id'], 'control', None))
            # From body to iteration
            if body_info and condition_stmt_info:
                for bb in body_info:
                    relations.append((bb['id'], condition_stmt_info['id'], 'control', None))
                # relations.append((body_stmt_info['id'], iteration_expr_info['id'], 'control', None))
            # From iteration back to condition (loop back edge)
            if condition_stmt_info and condition_info:
                relations.append((condition_stmt_info['id'], condition_info['id'], 'control', None))
            # Exit relation when condition fails
            if condition_info:
                relations.append((condition_info['id'], 'exit', 'control', None))
        elif ctx.doWhileStatement():
            stmt_ctx = ctx.doWhileStatement()
            condition_ctx = stmt_ctx.expression()
            condition_info,condition_relations = self._compute_expression_hash(condition_ctx)
            normalized_output, original_output = self._get_normalized_text(condition_ctx.start.tokenIndex, condition_ctx.stop.tokenIndex)
            normalized_output = f'while({normalized_output})'
            original_output = f'while ({original_output})'
            stmt_hash = hashString(normalized_output)
            stmt_id = stmt_hash[:6]
            stmt_info = {
                'id': stmt_id,
                'type': 'do_while',
                'hash': stmt_hash,
                'normalized_code': normalized_output,
                'original_code': original_output,
                'start_line': stmt_ctx.start.line,
                'end_line': stmt_ctx.stop.line,
                'condition': condition_info,
                'body': None,
            }
            self._check_woth_vuln_code(stmt_info)
            body_ctx = stmt_ctx.statement()
            body_info, body_relations = _process_statement_info(body_ctx, variable_definitions)
            stmt_info['body'] = body_info
            relations.extend(body_relations)
            if not isinstance(body_info, list):
                body_info = [body_info]
            stmt_info = [stmt_info]
            stmt_info.extend(body_info)
            
            if condition_info and body_info:
                for bb in body_info:
                    relations.append((condition_info['id'], bb['id'], 'control', None))
                    relations.append((bb['id'], condition_info['id'], 'control', None))
                relations.append((condition_info['id'], 'exit', 'control', None))
        elif ctx.whileStatement():
            stmt_ctx = ctx.whileStatement()
            condition_ctx = stmt_ctx.expression()
            condition_info,condition_relations = self._compute_expression_hash(condition_ctx)
            normalized_output, original_output = self._get_normalized_text(condition_ctx.start.tokenIndex, condition_ctx.stop.tokenIndex)
            normalized_output = f'while({normalized_output})'
            original_output = f'while ({original_output})'
            stmt_hash = hashString(normalized_output)
            stmt_id = stmt_hash[:6]
            stmt_info = {
                'id': stmt_id,
                'type': 'while',
                'hash': stmt_hash,
                'normalized_code': normalized_output,
                'original_code': original_output,
                'start_line': stmt_ctx.start.line,
                'end_line': stmt_ctx.stop.line,
                'condition': condition_info,
                'body': None,
            }
            self._check_woth_vuln_code(stmt_info)
            relations.extend(condition_relations)
            
            if stmt_ctx.statement():
                body_ctx = stmt_ctx.statement()
                body_info, body_relations = _process_statement_info(body_ctx, variable_definitions)
                stmt_info['body'] = body_info
                relations.extend(body_relations)
                stmt_info = [stmt_info]               
                if not isinstance(body_info, list):
                    body_info = [body_info]
                stmt_info.extend(body_info)
            else:
                body_ctx = stmt_ctx.block()
                body_info, body_relations = self._compute_block_hash(body_ctx, variable_definitions)
                stmt_info['body'] = body_info
                relations.extend(body_relations)
                stmt_info = [stmt_info]
                stmt_info.extend(body_info)

            if condition_info and body_info:
                for bb in body_info:
                    relations.append((condition_info['id'], bb['id'], 'control', None))
                    relations.append((bb['id'], condition_info['id'], 'control', None))
            relations.append((condition_info['id'], 'exit', 'control', None))
        elif ctx.uncheckedStatement():
            block_ctx = ctx.uncheckedStatement().block()
            body_info, body_relations = self._compute_block_hash(block_ctx, variable_definitions)
            stmt_info = []
            for bb in body_info:
                bb['type'] = 'unchecked'
                stmt_info.append(bb)
            relations.extend(body_relations)
        elif ctx.inlineAssemblyStatement():
            stmt_ctx = ctx.inlineAssemblyStatement()
            assembly_block = stmt_ctx.assemblyBlock()
            if assembly_block:
                # For simplicity, we'll treat the entire assembly block as a single unit
                assembly_start = assembly_block.start.tokenIndex
                assembly_stop = assembly_block.stop.tokenIndex
                assembly_normalized, assembly_original = self._get_normalized_text(assembly_start, assembly_stop)
                assembly_hash = hashString(assembly_normalized)
                assembly_id = assembly_hash[:6]
                stmt_info = {
                    'id': assembly_id,
                    'type': 'assembly_block',
                    'hash': assembly_hash,
                    'normalized_code': assembly_normalized,
                    'original_code': assembly_original,
                    'start_line': assembly_block.start.line,
                    'end_line': assembly_block.stop.line,
                }
                # Record control flow relation
                self._check_woth_vuln_code(stmt_info)
                relations.append((stmt_info['id'], assembly_id, 'control', None))
        elif ctx.simpleStatement():
            stmt_ctx = ctx.simpleStatement()
            if stmt_ctx.variableDeclarationStatement():
                var_decl_ctx = stmt_ctx.variableDeclarationStatement()
                # Process variable declaration statement
                start_token_index = var_decl_ctx.start.tokenIndex
                stop_token_index = var_decl_ctx.stop.tokenIndex
                normalized_output, original_output = self._get_normalized_text(start_token_index, stop_token_index)
                stmt_hash = hashString(normalized_output)
                stmt_id = stmt_hash[:6]
                # Extract variable names
                variable_names = []
                var_decl = var_decl_ctx.variableDeclaration()
                if var_decl is None:
                    var_decl = var_decl_ctx.variableDeclarationList().variableDeclaration(0) if var_decl_ctx.variableDeclarationList() else None   
                if (var_decl is not None) and (var_decl.identifier()):             
                    var_name = var_decl.identifier().getText()
                    variable_names.append(var_name)
                    variable_definitions[var_name] = stmt_id  # Record definition
                stmt_info = {
                    'id': stmt_id,
                    'type': 'variable_declaration',
                    'hash': stmt_hash,
                    'normalized_code': normalized_output,
                    'original_code': original_output,
                    'variables': variable_names,
                    'start_line': var_decl_ctx.start.line,
                    'end_line': var_decl_ctx.stop.line,
                }
                self._check_woth_vuln_code(stmt_info)
            elif stmt_ctx.expressionStatement():
                expr_stmt_ctx = stmt_ctx.expressionStatement()
                expression_ctx = expr_stmt_ctx.expression()
                expr_info, expr_relations = self._compute_expression_hash(expression_ctx)
                relations.extend(expr_relations)
                stmt_info = {
                    'id': expr_info['id'],
                    'type': 'expression_statement',
                    'hash': expr_info['hash'],
                    'normalized_code': expr_info['normalized_code'],
                    'original_code': expr_info['original_code'],
                    'variables': expr_info['variables'],
                    'start_line': expr_stmt_ctx.start.line,
                    'end_line': expr_stmt_ctx.stop.line,
                }
                self._check_woth_vuln_code(stmt_info)
                # Record data flow relations
                for var_name in expr_info['variables']:
                    if var_name in variable_definitions:
                        def_stmt_id = variable_definitions[var_name]
                        relations.append((def_stmt_id, stmt_info['id'], 'data', var_name))
        else:
            stmt_info,relations = _process_statement_info(ctx)
        if isinstance(stmt_info, list):
            return stmt_info, relations
        else:
            if len(stmt_info) > 0:
                return [stmt_info], relations
            else:
                return [], relations

    def _extract_function_info(self, ctx:SolidityParser.FunctionDefinitionContext):
        start_token_index = ctx.start.tokenIndex
        stop_token_index = ctx.stop.tokenIndex
        normalized_output, original_output = self._get_normalized_text(start_token_index, stop_token_index)
        function_hash = hashString(normalized_output)
        
        input_params = []
        output_params = []
        if ctx.parameterList():
            if ctx.parameterList().parameter():
                for p in ctx.parameterList().parameter():
                    if p.identifier():
                        input_params.append(p.identifier().getText())
                    else:
                        input_params.append(p.getText())
        if ctx.returnParameters():
            if ctx.returnParameters().parameterList():
                if ctx.returnParameters().parameterList().parameter():
                    for p in ctx.returnParameters().parameterList().parameter():
                        if p.identifier():
                            output_params.append(p.identifier().getText())
                        else:
                            output_params.append(p.getText())
                                    
        function_name = ctx.identifier().getText() if ctx.identifier() else ''
        visibility = 'default'
        if ctx.modifierList().ExternalKeyword():
            visibility = 'external'
        elif ctx.modifierList().PublicKeyword():
            visibility = 'public'
        elif ctx.modifierList().InternalKeyword():
            visibility = 'internal'
        elif ctx.modifierList().PrivateKeyword():
            visibility = 'private'
        state_mutability = ctx.modifierList().stateMutability()[0].getText() if ctx.modifierList().stateMutability() else 'default'
        is_virtual = 'virtual' in ctx.modifierList().getText()
        is_override = 'override' in ctx.modifierList().getText()

        # Check if function has a body
        has_body = (ctx.block() is not None) and (ctx.block().statement() is not None)
        statements = ctx.block().statement() if has_body else []
        processed_statements = []
        function_relations = []
        variable_definitions = {}
        function_calls = []
        self.function_variables = set()
        if has_body:
            matches = re.findall(r'(?<!function\s)\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', ctx.block().getText())
            for f in matches:
                if f not in ['add','sub','require','address']:
                    if 'emit' not in f:
                        function_calls.append(f)
        dfg = CodePropertyGraph()
        start_index = dfg.add_node('START','START')
        for input_param in input_params:
            index = dfg.add_node(input_param, 'VAR')
            dfg.add_edge(start_index, index, order_incur=False)
        dfg._order_incur()          
        last_var_index_cached = []  
        last_last = []            
        for statement in statements:
            stmt_info, stmt_relations = self._compute_statement_hash(statement,variable_definitions)
            if stmt_info:
                processed_statements.extend(stmt_info)
                function_relations.extend(stmt_relations)
            
            preserved_index = dfg._order_incur()
            variables, first_var_index, last_var_index = self._process_statement(statement, dfg)
            if last_var_index:
                self.function_variables.update(set(variables))
                for l in last_var_index_cached:
                    for f in first_var_index:
                        dfg.add_edge(l, f, cached_order=preserved_index)
                temp = [l for l in last_var_index if ('CON' in l)]
                if len(temp) > 0:
                    last_var_index_cached = temp
                last_last = last_var_index
            elif (len(variables)+len(first_var_index)+len(last_var_index)) == 0:
                pass
            else:
                for v in variables:
                    index_temp = dfg.add_node(v, 'VAR')
                    last_last.append(index_temp)
        if 'END' not in dfg.get_nodes():
            output_index = dfg.add_node('END','END')
            for l in last_last:
                dfg.add_edge(l, output_index, order_incur=False)
            dfg._order_incur()
            
        for i in range(len(processed_statements) - 1):
            current_stmt = processed_statements[i]
            next_stmt = processed_statements[i + 1]
            function_relations.append((current_stmt['id'], next_stmt['id'], 'control', None))

        function_info = {
            'name': function_name,
            'visibility': visibility,
            'stateMutability': state_mutability,
            'isVirtual': is_virtual,
            'isOverride': is_override,
            'has_body': has_body,
            'input_parameters': input_params,
            'return_parameters': output_params,
            'statements': processed_statements,
            'relations': function_relations,
            'function_calls': function_calls,
            'function_variables': list(self.function_variables),
            'dfg': dfg,
            'hash': function_hash,
            'normalized_code': normalized_output,
            'original_code': original_output,
            'start_line': (ctx.start.line, ctx.start.column, ctx.start.start),
            'end_line': (ctx.stop.line, ctx.stop.column, ctx.stop.stop),
        }
        self.function_global[self.current_function] = deepcopy(function_info)
        return function_info

    def _extract_contract_info(self, ctx:SolidityParser.ContractDefinitionContext):
        start_token_index = ctx.start.tokenIndex
        stop_token_index = ctx.stop.tokenIndex

        normalized_output, original_output = self._get_normalized_text(start_token_index, stop_token_index)
        contract_hash = hashString(normalized_output)

        # Extract contract name
        contract_name = ctx.identifier().getText()

        # Determine contract type
        if ctx.ContractKeyword():
            contract_type = 'contract'
        elif ctx.InterfaceKeyword():
            contract_type = 'interface'
        elif ctx.LibraryKeyword():
            contract_type = 'library'
        elif ctx.AbstractKeyword():
            contract_type = 'abstract'
        else:
            contract_type = 'unknown'

        # Extract inheritance
        inheritance_list = []
        for inheritance_specifier in ctx.inheritanceSpecifier():
            inheritance_list.append(inheritance_specifier.userDefinedTypeName().getText())

        return {
            'name': contract_name,
            'hash': contract_hash,
            'normalized_code': normalized_output,
            'original_code': original_output,
            'type': contract_type,
            'inheritance': inheritance_list,
            'start_line': ctx.start.line,
            'end_line': None,  # Will be updated in exitContractDefinition
            'functions': {},
            'events': [],
            'state_variables': [],
        }

    def _get_position(self, ctx):
        return ctx.start.line, ctx.stop.line if ctx.stop else ctx.start.line

    ### For code property graph
    def _process_expression(self, ctx: SolidityParser.ExpressionContext, dfg:CodePropertyGraph):
        variables = []
        expression_list = []
        first_expr = []
        last_expr = []
        if hasattr(ctx, 'functionCallArguments') and ctx.functionCallArguments():
            vars, first_expr, last_args = self._process_expression(ctx.functionCallArguments(),dfg)
            var_left = []
            for child in ctx.expression(0).children:
                child_vars, child_first_expr, child_last_expr = self._process_expression(child,dfg)
                variables.extend(child_vars)
                first_expr.extend(child_first_expr)
                child_index = dfg.add_node(child.getText(), 'ACT', {'details':child.getText()})
                for l in child_last_expr:
                    dfg.add_edge(l, child_index, order_incur=False)
                dfg._order_incur()
                last_args.append(child_index)
            # # parts = ctx.expres sion(0).getText().split('.') if '.' in ctx.expression(0).getText() else []
            # if len(parts) > 1:
            #     parts = parts[:-1]
            # for part in parts:
            #     if part in ['msg','this']:
            #         continue
            #     if part.endswith(')'):
            #         var_left.append(dfg.add_node(part, 'ACT', {'details':part}))
            #     else:
            #         var_left.append(dfg.add_node(part, 'VAR', {'details':part}))
            #         vars.append(part)
            function_call_index = dfg.add_node(ctx.getText(), 'ACT',{'details':ctx.getText()})
            for l in last_args:
                dfg.add_edge(l, function_call_index,order_incur=False)
            for l in var_left:
                dfg.add_edge(l, function_call_index,order_incur=False)
            dfg._order_incur()
            variables.extend(vars)
            first_expr.extend(var_left)
            last_expr = [function_call_index]
        elif hasattr(ctx, 'expressionList') and ctx.expressionList():
            for expr in ctx.expressionList().expression():
                vars, first_expr_temp, last_expr_temp = self._process_expression(expr,dfg)
                variables.extend(vars)
                first_expr.extend(first_expr_temp)
                last_expr.extend(last_expr_temp)
        elif isinstance(ctx,SolidityParser.NameValueListContext):
            for expr in ctx.nameValue():
                vars, first_expr_temp, last_expr_temp = self._process_expression(expr,dfg)
                variables.extend(vars)
                first_expr.extend(first_expr_temp)
                last_expr.extend(last_expr_temp)
        elif ctx.getChildCount() == 3:
            op = ctx.getChild(1).getText()
            if op == '=':
                left_var, left_first, left_last = self._process_expression(ctx.getChild(0),dfg)
                right_var, right_first, right_last = self._process_expression(ctx.getChild(2),dfg)
                right_index = dfg.add_node(ctx.getChild(2).getText(), 'ACT', {'details':ctx.getChild(2).getText()})
                for r in right_last:
                    if r != right_index:
                        dfg.add_edge(r, right_index, order_incur=False)
                dfg._order_incur()
                for l in left_last:
                    dfg.add_edge(right_index, l, order_incur=False)
                dfg._order_incur()
                last_expr = left_last
                first_expr = right_first       
            elif op in ['.',':','=','+=','-=','*=','/=','%=','^=','|=','&=','<<=','>>=','>>>=','!=','==','<','>','<=','>=','&&','||','&','|','^','<<','>>','>>>','+','-','*','/','%']:
                left_var, left_first, left_last = self._process_expression(ctx.getChild(0),dfg)
                right_var, right_first, right_last = self._process_expression(ctx.getChild(2),dfg)
                action_index = dfg.add_node(ctx.getText(), 'ACT', {'details':ctx.getText(),'op':op})
                variables.extend(left_var)
                first_expr = left_first
                for l in left_last:
                    dfg.add_edge(l, action_index, order_incur=False)
                if (op != '.') or (ctx.getChild(0).getText() not in ['this','msg']):
                    variables.extend(right_var)
                    first_expr.extend(right_first)
                    for r in right_last:
                        dfg.add_edge(r, action_index, order_incur=False)
                dfg._order_incur()
                last_expr = [action_index]   
            else:
                for child in ctx.children:
                    vars, first_expr_temp, last_expr_temp = self._process_expression(child,dfg)
                    variables.extend(vars)
                    first_expr.extend(first_expr_temp)
                    last_expr.extend(last_expr_temp)
                action = dfg.add_node(ctx.getText(), 'ACT', {'details':ctx.getText()})
                for l in last_expr:
                    dfg.add_edge(l, action, order_incur=False)
                dfg._order_incur()
                last_expr = [action]
        elif hasattr(ctx, 'expression') and ctx.expression():
            if isinstance(ctx.expression(), list):
                pattern = re.compile(r'\b(\w+)\[(\w+)\]')
                matches = pattern.findall(ctx.getText())
                if matches:
                    variables.append(matches[0][0])
                    variables.append(matches[0][1])
                    var1 = dfg.add_node(matches[0][0], 'ARRAY')
                    var2 = dfg.add_node(matches[0][1], 'VAR')
                    action = dfg.add_node(ctx.getText(), 'ARRAY[VAR]')
                    dfg.add_edge(var1, action, order_incur=False)
                    dfg.add_edge(var2, action, order_incur=False)
                    dfg._order_incur()
                    first_expr = [var1,var2]
                    last_expr = [action]
                else:
                    for expr in ctx.expression():
                        vars, first_expr_temp, last_expr_temp = self._process_expression(expr,dfg)
                        variables.extend(vars)
                        first_expr.extend(first_expr_temp)
                        last_expr.extend(last_expr_temp)
                    if ctx.getText().startswith('!'):
                        action = dfg.add_node(ctx.getText(), 'ACT', {'details':ctx.getText()})
                        for l in last_expr:
                            dfg.add_edge(l, action, order_incur=False)
                        dfg._order_incur()
                        last_expr = [action]
            else:
                vars, first_expr_temp, last_expr_temp = self._process_expression(ctx.expression(),dfg)
                variables.extend(vars)
                first_expr.extend(first_expr_temp)
                last_expr.extend(last_expr_temp)
        elif ctx.getChildCount() == 0:
            pass
        elif ctx.getChildCount() == 1:
            if hasattr(ctx, 'primaryExpression') and ctx.primaryExpression():
                if ctx.primaryExpression().tupleExpression():
                    index_temp = []
                    for v in ctx.primaryExpression().tupleExpression().expression():
                        variables.append(v.getText())
                        index_temp.append(dfg.add_node(v.getText(), 'VAR'))
                    first_expr = index_temp
                    last_expr = index_temp
                else:
                    variables.append(ctx.getText())
                    index = [dfg.add_node(ctx.getText(), 'VAR')]
                    first_expr = index
                    last_expr = index
                    pass
            elif '[' in ctx.getText():
                array_content = ctx.expressionList().expression(0).expression(0).getText()
                array_inner_content = ctx.expressionList().expression(0).expression(1).getText()
                content = ctx.getText()
                variables.append(array_content)
                variables.append(array_inner_content)
                variables.append(content)
                array_content_index = dfg.add_node(array_content, 'ARRAY',{})
                array_content_inner_index = dfg.add_node(array_inner_content, 'VAR',{})
                array_content_index2 = dfg.add_node(array_content, 'ARRAY[VAR]',{'detail':content})
                dfg.add_edge(array_content_index, array_content_index2,order_incur=False)
                dfg.add_edge(array_content_inner_index, array_content_index2,order_incur=False)
                dfg._order_incur()
                first_expr = [array_content_index,array_content_inner_index]
                last_expr = [array_content_index2]
            else:
                variables.append(ctx.getText())
                index = dfg.add_node(ctx.getText(), 'VAR',{})
                first_expr = [index]
                last_expr = [index]
                pass
        elif any(ctx.getText().replace(';','').endswith(op) for op in ('++', '--')):
            if ctx.expression() and len(ctx.expression()) == 1:
                left_var, left_first, left_last = self._process_expression(ctx.expression(0), dfg)
                variables.extend(left_var)
                action_index = dfg.add_node(ctx.getText(), 'ACT', {'details':ctx.getText()})
                for l in left_last:
                    dfg.add_edge(l, action_index, order_incur=False)
                dfg._order_incur()
                for f in left_first:
                    dfg.add_edge(action_index, f, order_incur=False)
                dfg._order_incur()
                last_expr = [action_index]
                first_expr = left_first
            else:
                for expr in ctx.expression():
                    vars, expr_list = self._process_expression(expr, dfg)
                    variables.extend(vars)
                    expression_list.extend(expr_list)
        else:    
            variables.append(ctx.getText())
            index = dfg.add_node(ctx.getText(), 'VAR',{})
            first_expr = [index]
            last_expr = [index]      
            pass
        return variables, first_expr, last_expr
       
    def _process_loop_condition(self, ctx:SolidityParser.ExpressionContext, dfg: CodePropertyGraph, is_for=False):
        if is_for:
            variables = []
            initial_stmt_ctx = ctx.simpleStatement()
            init_text = ';'
            init_var = []
            init_first = []
            init_last = []
            if initial_stmt_ctx:
                init_var,init_first,init_last = self._process_simple_statement(initial_stmt_ctx, dfg)
                variables.extend(init_var)
                init_text = initial_stmt_ctx.getText()
                
            condition_text = ';'
            condition_var = []
            condition_first = []
            condition_last = []
            if ctx.expressionStatement():
                condition_ctx = ctx.expressionStatement().expression()
                if condition_ctx:
                    condition_var, condition_first, condition_last = self._process_condition_expression(condition_ctx, dfg)
                    variables.extend(condition_var)
                    condition_text = condition_ctx.getText()

            iteration_text = ''
            iteration_var = []
            iter_first = []
            iter_last = []
            iteration_ctx = ctx.expression()
            if iteration_ctx:
                iteration_var, iter_first, iter_last = self._process_expression(iteration_ctx, dfg)
                variables.extend(iteration_var)
                iteration_text = iteration_ctx.getText()
            
                
            for_statement_detail = {
                'initial_stmt': {
                    'original': init_text,
                    'variables': init_var
                    },
                'condition': {
                    'original': condition_text,
                    'variables': condition_var
                    },
                'iteration': {
                    'original': iteration_text,
                    'variables': iteration_var
                    }
                }
            
            for_stmt = f'{init_text}{condition_text}{iteration_text}'
            for_stmt_index = dfg.add_node(for_stmt, 'LOOP',details=for_statement_detail)
            first_var_index = init_first + condition_first + iter_first
            for l in init_last:
                dfg.add_edge(l, for_stmt_index,order_incur=False)
            for l in condition_last:
                dfg.add_edge(l, for_stmt_index,order_incur=False)
            for l in iter_last:
                dfg.add_edge(l, for_stmt_index,order_incur=False)
            dfg._order_incur()
                        
            return variables, first_var_index, [for_stmt_index]
        else:
            condition_ctx = ctx.expression()
            variables,first_var_index,condition_last = self._process_expression(condition_ctx, dfg)
            condition_index = dfg.add_node(condition_ctx.getText(), 'CON',details={'detail':condition_ctx.getText()})
            
            for condition in condition_last:
                dfg.add_edge(condition, condition_index,order_incur=False)
            dfg._order_incur()
            
            return variables, first_var_index, [condition_index]

    def _process_loops(self, ctx:SolidityParser.StatementContext, dfg: CodePropertyGraph, is_for=False):
        variables, first_var_index, last_index_cached = self._process_loop_condition(ctx, dfg, is_for)
        if ctx.statement():
            body_ctx = ctx.statement()
            vars, first_temp, last_temp = self._process_statement(body_ctx, dfg)
            variables.extend(vars)
            if first_temp:
                for f in first_temp:
                    for l in last_index_cached:
                        dfg.add_edge(l, f,order_incur=False)
                dfg._order_incur()
                last_index_cached = last_temp
        return variables, first_var_index, last_index_cached
    
    def _process_single_expression(self,expression:list, dfg:CodePropertyGraph):
        in_index = None
        out_index = None
        if expression[2] == 'ACTION':
            in_index = dfg.add_node(expression[0], 'VAR')
            out_index = dfg.add_node(f'{expression[1]}({expression[0]})', 'ACT')
            dfg.add_edge(in_index, out_index,order_incur=False)
        elif expression[0] == '':
            out_index = dfg.add_node(expression[1], 'VAR')
            in_index = out_index
        else:
            in_index = dfg.add_node(expression[0], 'VAR')
            out_index = dfg.add_node(expression[1], 'VAR')
            dfg.add_edge(in_index, out_index,order_incur=False)
        return in_index, out_index
            
    def _process_question_mark_expression_list(self, expression_list:list, dfg: CodePropertyGraph):
        variables = []
        first_var_index = None
        last_var_index = None
        condition = expression_list[0]
        condition_text = f'{condition[1]}{condition[2]}{condition[0]}'
        condition_left_index = dfg.add_node(condition[1], 'VAR')
        condition_right_index = dfg.add_node(condition[0], 'VAR')
        condition_index = dfg.add_node(condition_text, 'CON')
        dfg.add_edge(condition_left_index, condition_index,order_incur=False)
        dfg.add_edge(condition_right_index, condition_index)

        yes_in_index, yes_out_index = self._process_single_expression(expression_list[1], dfg)
        no_in_index, no_out_index = self._process_single_expression(expression_list[2], dfg)
        dfg._order_incur()
        dfg.add_edge(condition_index, yes_in_index,order_incur=False,label='YES')
        dfg.add_edge(condition_index, no_in_index,label='NO')
        first_var_index = [condition_left_index, condition_right_index]
        last_var_index = [yes_out_index, no_out_index]
        return variables, first_var_index, last_var_index
    
    def _process_statement_with_question_mark(self, expression_list:list, dfg: CodePropertyGraph):
        variables = []
        first_expression_index = None
        last_expression_index = None
        if len(expression_list) == 3:
            vars, first_expression_index, last_expression_index_temp = self._process_question_mark_expression_list(expression_list, dfg)
            variables.extend(vars)
            pass
        elif len(expression_list) == 4:
            vars, first_expression_index, last_expression_index_temp = self._process_question_mark_expression_list(expression_list[:3], dfg)
            variables.extend(vars)
            if expression_list[3][0] == '':
                temp_var_index = dfg.add_node(expression_list[3][1], 'VAR')
                for l in last_expression_index_temp:
                    dfg.add_edge(l, temp_var_index,order_incur=False)
                dfg._order_incur()
                last_expression_index = [temp_var_index]
            else:
                temp_var_index = dfg.add_node(expression_list[3][0], 'VAR')
                temp_var_index2 = dfg.add_node(expression_list[3][1], 'ACT')
                variables.append(expression_list[3][0])
                dfg.add_edge(temp_var_index, temp_var_index2)
                for l in last_expression_index_temp:
                    dfg.add_edge(l, temp_var_index,order_incur=False)
                dfg._order_incur()
                last_expression_index = [temp_var_index2]
        else:
            pass
        return variables, first_expression_index, last_expression_index

    def _process_expression_statement(self, ctx: SolidityParser.ExpressionStatementContext, dfg: CodePropertyGraph):
        expression_ctx = ctx.expression()
        variables, first_expression_index, last_expression_index = self._process_expression(expression_ctx, dfg)
        return variables, first_expression_index, last_expression_index
    
    def _process_simple_statement(self, ctx: SolidityParser.SimpleStatementContext, dfg: CodePropertyGraph):
        variables = []
        first_var_index = []
        last_var_index = []
        if ctx.variableDeclarationStatement():
            var_decl_ctx = ctx.variableDeclarationStatement()
            var_decl = None
            if var_decl_ctx.variableDeclaration():
                var_decl = [var_decl_ctx.variableDeclaration()]
            elif var_decl_ctx.variableDeclarationList():
                var_decl = var_decl_ctx.variableDeclarationList().variableDeclaration()
            if var_decl:
                var_index = []
                for v in var_decl:
                    var_name = v.identifier().getText()
                    var_type = v.typeName().getText()
                    variables.append(var_name)  
                    var_index.append(dfg.add_node(name=var_name, type='VAR', details={'type':var_type}))
                if var_decl_ctx.expression():
                    vars, first_var_index, last_expr = self._process_expression(var_decl_ctx.expression(), dfg)
                    variables.extend(vars)
                    for l in last_expr:
                        for v in var_index:
                            dfg.add_edge(l, v, order_incur=False)
                    dfg._order_incur()
                    last_var_index = var_index
            elif var_decl_ctx.identifierList():
                identifiers = var_decl_ctx.identifierList().identifier()
                var_names = [id.getText() for id in identifiers]
                variables = var_names
                self.function_variables.update(var_names)
                if var_decl_ctx.expression():
                    vars, first_var_index,last_var_index = self._process_expression(var_decl_ctx.expression(), dfg)
                    variables.extend(vars)
                else:
                    pass
        elif ctx.expressionStatement():
            variables, first_var_index, last_var_index = self._process_expression_statement(ctx.expressionStatement(), dfg)
        else:
            pass
        return variables, first_var_index, last_var_index
    
    def _process_condition_expression(self, condition_ctx: SolidityParser.ExpressionContext, dfg: CodePropertyGraph):
        if isinstance(condition_ctx, list):
            condition_ctx = condition_ctx[0]
        condition_index = dfg.add_node(condition_ctx.getText(), 'CON',details={'detail':condition_ctx.getText()})
        variables, first_var_index, last_var_index = self._process_expression(condition_ctx, dfg)
        return variables, first_var_index, [condition_index]
    
    def _process_block_statement(self, ctx: SolidityParser.BlockContext, dfg: CodePropertyGraph):
        variables = []
        first_var_index = []
        last_var_index = []
        statements = ctx.statement()
        for statement in statements:
            var, first_var_index_temp, last_var_index_temp = self._process_statement(statement, dfg)
            if len(first_var_index_temp) == 0:
                continue
            if len(first_var_index) == 0:
                first_var_index = first_var_index_temp
            variables.extend(var)
            if last_var_index_temp:
                last_var_index = last_var_index_temp
        return variables, first_var_index, last_var_index                     
                                
    def _process_statement(self, ctx: SolidityParser.StatementContext, dfg: CodePropertyGraph):
        variables = []
        first_var_index = []
        last_var_index = []
        if ctx is None:
            return variables,first_var_index,last_var_index
        if isinstance(ctx, SolidityParser.SimpleStatementContext):
            variables, first_var_index, last_var_index = self._process_simple_statement(ctx, dfg)
        elif hasattr(ctx, 'block') and ctx.block():
            if isinstance(ctx.block(), list):
                block = ctx.block()[0]
            else:
                block = ctx.block()
            variables, first_var_index, last_var_index = self._process_block_statement(block, dfg)
        elif ctx.simpleStatement():
            variables, first_var_index, last_var_index = self._process_simple_statement(ctx.simpleStatement(), dfg)
        elif ctx.returnStatement():
            return_stmt_ctx = ctx.returnStatement()
            if return_stmt_ctx.expression():
                expression_ctx = return_stmt_ctx.expression()
                vars, first_var_index, last_var_index = self._process_expression(expression_ctx, dfg)
                variables.extend(vars)
                end_index = dfg.add_node('END', 'END')
                for l in last_var_index:
                    dfg.add_edge(l, end_index,order_incur=False)
                dfg._order_incur()
                last_var_index = [end_index]
            else:
                index = dfg.add_node('END', 'END')
                last_var_index = [index]
                first_var_index = [index]
        elif ctx.requireStatement():
            require_stmt_ctx = ctx.requireStatement()
            condition_ctx = require_stmt_ctx.expression()
            if condition_ctx:
                vars, first_var_index, last_var_index = self._process_condition_expression(condition_ctx, dfg)  # TODO: condition_index (last_var_index)
                variables.extend(vars)
        elif ctx.ifStatement():
            if_stmt_ctx = ctx.ifStatement()
            condition_ctx = if_stmt_ctx.expression()
            if condition_ctx:
                vars, first_var_index, last_var_index_temp = self._process_condition_expression(condition_ctx, dfg)  # TODO: condition_index (last_var_index)
                variables.extend(vars)
                             
                if if_stmt_ctx.block():
                    vars, first_var_index_temp, last_var_index = self._process_block_statement(if_stmt_ctx.block(0), dfg)
                    for l in last_var_index_temp:
                        for f in first_var_index_temp:
                            dfg.add_edge(l, f,order_incur=False,label='IF')  
                    dfg._order_incur()                  
                    if len(if_stmt_ctx.block()) > 1:
                        else_block = if_stmt_ctx.block(1)
                        vars, first_var_index_else, last_var_index_else = self._process_block_statement(else_block, dfg)
                        if first_var_index_else is not None:
                            for l in last_var_index_temp:
                                for i in first_var_index_else:
                                    dfg.add_edge(l, i,order_incur=False,label='ELSE')
                            dfg._order_incur()
                            variables.extend(vars)
                            last_var_index.extend(last_var_index_else)
                        else:
                            pass
                    if len(if_stmt_ctx.block()) > 2:
                        pass
                else:
                    last_var_index = last_var_index_temp
        elif ctx.forStatement():
            for_stmt_ctx = ctx.forStatement()
            variables, first_var_index, last_var_index = self._process_loops(for_stmt_ctx, dfg, True)
        elif ctx.whileStatement():
            while_stmt_ctx = ctx.whileStatement()
            variables, first_var_index, last_var_index = self._process_loops(while_stmt_ctx, dfg)
        elif ctx.doWhileStatement():
            do_while_stmt_ctx = ctx.doWhileStatement()
            variables, first_var_index, last_var_index = self._process_loops(do_while_stmt_ctx, dfg)
        elif ctx.uncheckedStatement():
            unchecked_stmt_ctx = ctx.uncheckedStatement()
            variables, first_var_index, last_var_index = self._process_statement(unchecked_stmt_ctx, dfg)
        elif ctx.getText().startswith('emit'):
            pass
        elif ctx.inlineAssemblyStatement():
            stmt_ctx = ctx.inlineAssemblyStatement()
            stmt_index = dfg.add_node(stmt_ctx.getText(), 'ASS')
            first_var_index = [stmt_index]
            last_var_index = [stmt_index]
        elif ctx.revertStatement():
            stmt_ctx = ctx.revertStatement()
            stmt_index = dfg.add_node(stmt_ctx.getText(),'ACT')
            first_var_index = [stmt_index]
            last_var_index = [stmt_index]
        elif ctx.tryStatement():
            stmt_ctx = ctx.tryStatement()
            if stmt_ctx.functionCall():
                variables, first_var_index, last_var_index = self._process_expression(stmt_ctx.functionCall().expression(),dfg)
                if stmt_ctx.block():
                    vars, first_temp, last_temp = self._process_block_statement(stmt_ctx.block(),dfg)
                    if first_temp:
                        variables.extend(vars)
                        for l in last_var_index:
                            for f in first_temp:
                                dfg.add_edge(l,f,order_incur=False)
                        dfg._order_incur()
                        last_var_index = last_temp
        else:
            pass
        return variables,first_var_index,last_var_index
    
    def _merge_graphs(self,functions_dict):
        for function in functions_dict:
            if functions_dict[function]['dfg']:
                dfg = functions_dict[function]['dfg']
                nodes = dfg.get_nodes()
                for node in nodes:
                    name = dfg.graph.nodes[node]['name']
                    if '(' in name:
                        name = name.split('(')[0]
                    if name in self.function_global:
                        if self.function_global[name]['dfg'] is not None:
                            functions_dict[function]['dfg'].update_graph(self.function_global[name]['dfg'],node.index)
                # functions_dict[function]['dfg'] = functions_dict[function]['dfg'].to_json()
                functions_dict[function]['dfg_hash'] = functions_dict[function]['dfg'].compute_hash()
        return functions_dict

    ### Listener functions
    def enterPragmaDirective(self, ctx:SolidityParser.PragmaDirectiveContext):
        if ctx.pragmaName().getText() == 'solidity':
            self.compiler_version = ctx.children[3].getText()

    def enterImportDirective(self, ctx: SolidityParser.ImportDirectiveContext):
        if len(self.contracts) == 1:
            if ctx.stop:
                if ctx.stop.line > self.last_line_of_import:
                    self.last_line_of_import = ctx.stop.line
        import_path = ctx.getText().replace('import ', '').replace(';', '').replace('"', '').replace("'", "").strip()
        self.imports.append(import_path)
        return super().enterImportDirective(ctx)

    def enterContractDefinition(self, ctx:SolidityParser.ContractDefinitionContext):
        if self.first_contract:
            self.first_contract = False
            self.last_line_of_import = ctx.start.line - 1

        # Process contract tokens
        contract_info = self._extract_contract_info(ctx)
        contract_name = contract_info['name']

        self.current_contract = contract_name
        self.contracts[contract_name] = contract_info
        self.contracts[contract_name]['imports'] = self.imports
        self.contracts[contract_name]['compiler_version'] = self.compiler_version

    def exitContractDefinition(self, ctx:SolidityParser.ContractDefinitionContext):
        self.contracts[self.current_contract]["end_line"] = ctx.stop.line
        if self.last_line_of_state_variables < self.first_line_of_function:
            self.contracts[self.current_contract]["state_variables_first"] = True
        else:
            self.contracts[self.current_contract]["state_variables_first"] = False
        self.contracts[self.current_contract]["state_variables_loc"] = {
            'start_line': self.first_line_of_state_variables,
            'end_line': self.last_line_of_state_variables
        }
        if self.isMainContract:
            self.contracts[self.current_contract]["isMainContract"] = True
            # self.contracts['ContractTest'] = self.contracts[self.current_contract]
            # if self.current_contract != 'ContractTest':
            #     del self.contracts[self.current_contract]
        
        if self.contracts[self.current_contract]['functions']:
            self.contracts[self.current_contract]['functions'] = self._merge_graphs(self.contracts[self.current_contract]['functions'])
        self._reset_contract_variables()

    def enterFunctionDefinition(self, ctx:SolidityParser.FunctionDefinitionContext):
        if self.first_line_of_function == -1:
            self.first_line_of_function = ctx.start.line

        # Process function tokens
        function_info = self._extract_function_info(ctx)
        function_name = function_info['name']

        if function_name.startswith('test'):
            self.isMainContract = True

        # Store the function info
        if self.current_contract:
            self.contracts[self.current_contract]["functions"][function_name] = function_info
        else:
            self.functions[function_name] = function_info

    def enterEventDefinition(self, ctx:SolidityParser.EventDefinitionContext):
        event_text = ctx.getText()
        self.contracts[self.current_contract]["events"].append(event_text)

    def enterStateVariableDeclaration(self, ctx:SolidityParser.StateVariableDeclarationContext):
        if ctx.identifier():
            variable_name = ctx.identifier().getText()
            start_line, end_line = self._get_position(ctx)
            if self.first_line_of_state_variables == -1:
                self.first_line_of_state_variables = start_line
            if end_line > self.last_line_of_state_variables:
                self.last_line_of_state_variables = end_line

            # Process state variable tokens
            start_token_index = ctx.start.tokenIndex
            stop_token_index = ctx.stop.tokenIndex
            normalized_output, original_output = self._get_normalized_text(start_token_index, stop_token_index)
            variable_hash = hashString(normalized_output)

            variable_info = {
                "name": variable_name,
                "type": ctx.typeName().getText(),
                "start_line": start_line,
                "end_line": end_line,
                "hash": variable_hash,
                "normalized_code": normalized_output,
                "original_code": original_output,
            }

            if self.current_contract:
                self.contracts[self.current_contract]["state_variables"].append(variable_info)
            else:
                self.global_state_variables.append(variable_info)
    

    def get_contracts_info(self):
        return {'contracts': self.contracts, 'functions': self._merge_graphs(self.functions), 'vuln_code_statements': self.vuln_code_statements}


def contract_parser(code,vuln_code):
    input_stream = antlr4.InputStream(code)
    lexer = SolidityLexer(input_stream)
    lexer.removeErrorListeners()
    token_stream = antlr4.CommonTokenStream(lexer)
    parser = SolidityParser(token_stream)
    parser.removeErrorListeners()
    tree = parser.sourceUnit()

    listener = ContractParser(token_stream,vuln_code)
    walker = antlr4.ParseTreeWalker()
    walker.walk(listener, tree)

    return listener


def parse_code(code,vuln_code=[]):
    listener = contract_parser(code,vuln_code)
    return listener.get_contracts_info()


def parse_file(f,vuln_code=[]):
    with open(f, 'r', encoding='utf-8') as file:
        code = file.read()    
    return parse_code(code,vuln_code)


if __name__ == '__main__':
    parse_file('./data/eth/00/00A0a01fef5A3210ea387BA725F0F9cA91BfE4DD_ARTSEETOKEN.sol')