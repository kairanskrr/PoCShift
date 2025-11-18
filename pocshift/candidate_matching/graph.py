import networkx as nx
from networkx.algorithms.graph_hashing import weisfeiler_lehman_graph_hash


class CodePropertyGraph:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.index_counter = {
            'VAR': 0,
            'ACT': 0,
            'CON': 0,
            'LOOP': 0,
            'ASS': 0,
            'ARRAY[VAR]': 0,
            'ARRAY': 0
        }
        self.name_mem = {}
        self.order = 0
        
    def _order_incur(self):
        self.order += 1
        return self.order
    
    def get_nodes(self):
        return list(self.graph.nodes)
        
    def add_node(self, name, type, details={}):
        if type in ['START', 'END']:
            index = type
        elif name in self.name_mem:
            index = self.name_mem[name]
        else:
            index = f"{type}{self.index_counter[type]}"
            self.name_mem[name] = index
            self.index_counter[type] += 1
        
        if not self.graph.has_node(index):
            self.graph.add_node(index, name=name, type=type, details=details)
        
        return index
        
    def add_edge(self, source, target, order_incur=True, label='', cached_order=None):
        if not self.graph.has_edge(source, target):
            self.graph.add_edge(source, target, order=cached_order or self.order, label=label)
            if order_incur:
                self._order_incur()
    
    def get_incoming_edges(self, index):
        return list(self.graph.predecessors(index))
    
    def get_outgoing_edges(self, index):
        return list(self.graph.successors(index))
    
    def update_graph(self, subgraph, index):
        index_incoming_edges = self.get_incoming_edges(index)
        if not index_incoming_edges:
            index_incoming_edges = [index]        
        graph_incoming_edges = subgraph.get_outgoing_edges('START')        
        index_mapping = {}
        for node in subgraph.graph.nodes(data=True):
            if node[0] not in ['START', 'END']:
                new_index = self.add_node(node[1]['name'], node[1]['type'], node[1]['details'])
                index_mapping[node[0]] = new_index

        for source, target, edge_data in subgraph.graph.edges(data=True):
            if source == 'START' or target == 'END':
                continue
            self.add_edge(index_mapping.get(source, source), index_mapping.get(target, target), label=edge_data.get('label'), cached_order=edge_data.get('order'))
        
        for i, edge in enumerate(graph_incoming_edges):
            if i < len(index_incoming_edges):
                self.add_edge(index_incoming_edges[i], index_mapping[edge])
        
    def to_json(self):
        return nx.node_link_data(self.graph, edges="links")
    
    def compute_hash(self):
        return weisfeiler_lehman_graph_hash(self.graph,node_attr='type')
    
    def draw_dfg_with_plotly(self, output_file, show=False):
        import networkx as nx
        import plotly.graph_objects as go
        
        # Compute positions for nodes
        pos = nx.spring_layout(self.graph, k=0.5, iterations=50)
        
        # Node properties
        node_x = []
        node_y = []
        node_text = []
        node_color = []
        
        type_color_mapping = {
            'START': 'lightgreen',
            'END': 'lightblue',
            'VAR': 'lightyellow',
            'CON': 'lightpink',
            'ACT': 'orange'
        }
        
        for node_id in self.graph.nodes():
            x, y = pos[node_id]
            node = self.graph.nodes[node_id]
            label = node['name']
            node_type = node['type']
            color = type_color_mapping.get(node_type, 'lightgrey')
            node_x.append(x)
            node_y.append(y)
            node_text.append(label)
            node_color.append(color)
        
        # Edge properties
        edge_x = []
        edge_y = []
        edge_annotations = []
        
        for edge in self.graph.edges():
            src, dst = edge
            x0, y0 = pos[src]
            x1, y1 = pos[dst]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
            label = self.graph.edges[edge].get('label', '')
            if label:
                edge_annotations.append(
                    dict(
                        x=(x0 + x1) / 2,
                        y=(y0 + y1) / 2,
                        text=label,
                        showarrow=False,
                        font=dict(size=10),
                        xanchor='center',
                        yanchor='bottom'
                    )
                )
        
        # Create edge trace
        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=1, color='#888'),
            hoverinfo='none',
            mode='lines')
        
        # Create node trace
        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            text=node_text,
            hoverinfo='text',
            marker=dict(
                color=node_color,
                size=40,
                line=dict(width=2, color='black')),
            textposition='top center')
        
        # Create the figure
        fig = go.Figure(data=[edge_trace, node_trace],
                        layout=go.Layout(
                            title='Data Flow Graph',
                            titlefont_size=16,
                            showlegend=False,
                            hovermode='closest',
                            margin=dict(b=20, l=5, r=5, t=40),
                            annotations=edge_annotations,
                            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                            dragmode='pan'  # Enable dragging
                        ))
        
        def highlight_path_to_node(clicked_node):
            """Highlight all paths to the clicked node."""
            # Find all predecessors and edges connecting to the clicked node
            predecessors = list(nx.ancestors(self.graph, clicked_node))
            predecessors.append(clicked_node)
            predecessor_edges = [(u, v) for u, v in self.graph.edges() if v in predecessors and u in predecessors]
            
            # Update node colors
            highlighted_node_colors = [
                '#FF0000' if node in predecessors else color
                for node, color in zip(self.graph.nodes(), node_color)
            ]
            
            # Update edge colors
            highlighted_edge_x = []
            highlighted_edge_y = []
            for src, dst in predecessor_edges:
                x0, y0 = pos[src]
                x1, y1 = pos[dst]
                highlighted_edge_x.extend([x0, x1, None])
                highlighted_edge_y.extend([y0, y1, None])
            
            # Update traces
            edge_trace.update(x=highlighted_edge_x, y=highlighted_edge_y, line=dict(color='#FF0000'))
            node_trace.update(marker=dict(color=highlighted_node_colors))
            fig.show()
    
        # Add click event handler
        def on_click(trace, points, state):
            clicked_node_idx = points.point_inds[0]
            clicked_node = list(self.graph.nodes())[clicked_node_idx]
            highlight_path_to_node(clicked_node)
        
        node_trace.on_click(on_click)
        
        # Save and optionally display the graph
        fig.write_html(output_file)
        if show:
            fig.show()


        
    def __str__(self):
        return f"Nodes: {list(self.graph.nodes(data=True))}\nEdges: {list(self.graph.edges(data=True))}"
    
    def __repr__(self):
        return self.__str__()
