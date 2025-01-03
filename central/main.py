from flask import Flask, request, jsonify, render_template, redirect, url_for, send_file, Response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import networkx as nx
import matplotlib.pyplot as plt
from io import BytesIO 

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ports.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class ConnectionResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)    
    agent_uuid = db.Column(db.String(36),nullable=False)
    agent_ip = db.Column(db.String(45), nullable=False)
    ip = db.Column(db.String(45), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(10), nullable=False)
    success = db.Column(db.Boolean, nullable=False)
    timestamp = db.Column(db.String(45), nullable=False)
    response = db.Column(db.Text, nullable=True)
    error = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f'<ConnectionResult {self.ip}:{self.port} - {self.status}>'

class Port(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    port_number = db.Column(db.Integer, nullable=False)
    
class Agent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), nullable=False)
    agent_uuid = db.Column(db.String(50), unique=True, nullable=False)
    last_seen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f'<Agent {self.agent_uuid}>'

# Ensure database tables are created within the application context
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    agents = Agent.query.order_by(Agent.last_seen.desc()).all()
    return render_template('index.html',agents=agents)

@app.route('/ports')
def ports():
    ports = Port.query.all()
    return render_template('ports.html', ports=ports)

@app.route('/add_port', methods=['POST'])
def add_port():
    data = request.get_json()
    port_number = data.get('port_number')
    if port_number:
        new_port = Port(port_number=port_number)
        db.session.add(new_port)
        db.session.commit()
        return jsonify(success=True, port={'id': new_port.id, 'port_number': new_port.port_number})
    return jsonify(success=False), 400

@app.route('/delete_port/<int:port_id>', methods=['DELETE'])
def delete_port(port_id):
    port = Port.query.get(port_id)
    if port:
        db.session.delete(port)
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'success': False}), 404

@app.route('/api/agent', methods=['POST'])
def receive_agent_callhome():
    data = request.get_json()
    if not data or 'ip_address' not in data or 'agent_uuid' not in data:
        return jsonify({'error': 'Invalid request data'}), 400

    ip_address = data['ip_address']
    agent_uuid = data['agent_uuid']

    # Log the received data (optional)
    print(f"Received request from IP: {ip_address}, UUID: {agent_uuid}")

    # Find existing agent or create a new one
    agent = Agent.query.filter_by(agent_uuid=agent_uuid).first()
    if agent:
        agent.ip_address = ip_address
        agent.last_seen = datetime.utcnow()
    else:
        agent = Agent(ip_address=ip_address, agent_uuid=agent_uuid, last_seen=datetime.utcnow())
        db.session.add(agent)

    db.session.commit()
    
    #Return current Agents and ports lists as a blob.
    ports = Port.query.all()
    agents = Agent.query.all()
    
    port_list = [{'id': port.id, 'port_number': port.port_number} for port in ports]
    agent_list = [{'id': agent.id, 'ip_address': agent.ip_address, 'agent_uuid': agent.agent_uuid, 'last_seen': agent.last_seen} for agent in agents]
    all_hosts_ports_return_data = {'ports': port_list, 'hosts': agent_list}
    return jsonify(all_hosts_ports_return_data), 200

@app.route('/api/results', methods=['POST'])
def receive_connection_results():
    data = request.get_json()
    agent_uuid = data.get('agent_uuid')
    connection_results = data.get('connection_results', {})
    print(data)
    sending_agent_data = Agent.query.filter_by(agent_uuid=agent_uuid).first()
    for ip, ports in connection_results.items():
        for port, result in ports.items():
            connection_result = ConnectionResult(
                agent_uuid=sending_agent_data.agent_uuid,
                agent_ip=sending_agent_data.ip_address,
                ip=ip,
                port=port,
                status=result.get('status'),
                success=result.get('bool'),
                timestamp=result.get('timestamp'),
                error=result.get('error')
            )
            db.session.add(connection_result)
    
    db.session.commit()
    return jsonify({'message': 'Connection results received successfully'}), 200

@app.route('/results')
def show_results():
    query = ConnectionResult.query

    # Filtering
    agent_uuid = request.args.get('agent_uuid')
    if agent_uuid:
        query = query.filter(ConnectionResult.agent_uuid.contains(agent_uuid))

    agent_ip = request.args.get('agent_ip')
    if agent_ip:
        query = query.filter(ConnectionResult.agent_ip.contains(agent_ip))
        
    port = request.args.get('port')
    if port:
        query = query.filter(ConnectionResult.port == port)


    # Sorting
    sort_by = request.args.get('sort_by', 'timestamp')
    if sort_by == 'timestamp':
        query = query.order_by(ConnectionResult.timestamp.desc())
    elif sort_by == 'status':
        query = query.order_by(ConnectionResult.status)
    elif sort_by == 'success':
        query = query.order_by(ConnectionResult.success)

    results = query.all()
    return render_template('results.html', results=results)

@app.route('/filter', methods=['GET'])
def filter_results():
    return render_template('filter.html')


@app.route('/graph')
def graph():
    # Create a directed graph instead of undirected
    G = nx.DiGraph()
    
    # Get unique results (latest status for each connection)
    connection_results = ConnectionResult.query\
        .order_by(ConnectionResult.timestamp.desc())\
        .all()

    # Create a color map for success/failure
    color_map = {True: 'green', False: 'red'}
    
    # Track edges for visualization
    edges = []
    edge_colors = []
    edge_labels = {}

    for result in connection_results:
        # Add nodes if they don't exist
        source = result.agent_ip
        target = result.ip
        
        if not G.has_node(source):
            G.add_node(source, node_type='agent')
        if not G.has_node(target):
            G.add_node(target, node_type='target')
            
        # Create edge key and add to graph
        edge = (source, target)
        edge_key = f"{result.port}"
        
        # Add edge with port as weight
        G.add_edge(source, target, 
                  port=result.port,
                  success=result.success)
        
        edges.append(edge)
        edge_colors.append(color_map[result.success])
        edge_labels[edge] = f"Port: {result.port}\n{'✓' if result.success else '✗'}"

    plt.figure(figsize=(12, 8))
    pos = nx.spring_layout(G, k=1, iterations=50)

    # Draw nodes with different colors for agents vs targets
    agent_nodes = [node for node, attr in G.nodes(data=True) if attr.get('node_type') == 'agent']
    target_nodes = [node for node, attr in G.nodes(data=True) if attr.get('node_type') == 'target']
    
    # Draw nodes
    nx.draw_networkx_nodes(G, pos, nodelist=agent_nodes, node_color='lightblue', 
                          node_size=2000, label='Agents')
    nx.draw_networkx_nodes(G, pos, nodelist=target_nodes, node_color='lightgreen',
                          node_size=2000, label='Targets')

    # Draw edges with colors based on success
    nx.draw_networkx_edges(G, pos, edge_color=edge_colors, arrows=True, 
                          arrowsize=20, width=2)

    # Add labels
    nx.draw_networkx_labels(G, pos, font_size=8)
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=8)

    plt.title('Network Connectivity Map\nGreen = Success, Red = Failure')
    plt.legend()
    
    # Save plot to BytesIO object
    img = BytesIO()
    plt.savefig(img, format='png', bbox_inches='tight', dpi=300)
    img.seek(0)
    plt.close()

    return send_file(img, mimetype='image/png')

@app.route('/api/test/ports', methods=['GET'])
def get_ports():
    ports = Port.query.all()
    port_list = [{'id': port.id, 'port_number': port.port_number} for port in ports]
    return jsonify(port_list)

@app.route('/metrics')
def metrics():
    # Get results from the last minute (adjust timeframe as needed)
    cutoff_time = (datetime.utcnow() - timedelta(minutes=1)).strftime('%Y-%m-%d %H:%M:%S')
    results = ConnectionResult.query.filter(ConnectionResult.timestamp >= cutoff_time).all()
    
    # Initialize metrics string
    metrics = []
    
    # Add help and type information
    metrics.extend([
        '# HELP firewall_connection_status Connection test results (1 = success, 0 = failure)',
        '# TYPE firewall_connection_status gauge',
        '',
        '# HELP firewall_connection_total Total number of connection attempts',
        '# TYPE firewall_connection_total counter',
        '',
        '# HELP firewall_node Information about network nodes',
        '# TYPE firewall_node gauge',
        '',
        '# HELP firewall_edge Information about network edges',
        '# TYPE firewall_edge gauge',
        ''
    ])
    
    # Track unique nodes and their types
    nodes = {}
    edges = {}
    
    for result in results:
        # Track nodes (both source and target)
        if result.agent_ip not in nodes:
            nodes[result.agent_ip] = {'type': 'agent', 'connections': 0}
        if result.ip not in nodes:
            nodes[result.ip] = {'type': 'target', 'connections': 0}
        
        # Update connection counts for nodes
        nodes[result.agent_ip]['connections'] += 1
        nodes[result.ip]['connections'] += 1
        
        # Track edges
        edge_key = (result.agent_ip, result.ip, result.port)
        if edge_key not in edges:
            edges[edge_key] = {'success': 0, 'failure': 0, 'total': 0}
        
        if result.success:
            edges[edge_key]['success'] += 1
        else:
            edges[edge_key]['failure'] += 1
        edges[edge_key]['total'] += 1
    
    # Add node metrics - one series for id and one for stats
    for ip, data in nodes.items():
        # Node identity metric
        metrics.append(f'firewall_node{{id="{ip}",node_type="{data["type"]}"}} 1')
        # Node stats metric
        metrics.append(f'firewall_node_stats{{id="{ip}",node_type="{data["type"]}",metric="connections"}} {data["connections"]}')
    
    # Add edge metrics
    for (src_ip, dst_ip, port), data in edges.items():
        success_rate = data['success'] / data['total'] if data['total'] > 0 else 0
        # Edge identity metric
        metrics.append(f'firewall_edge{{source="{src_ip}",target="{dst_ip}",port="{port}"}} 1')
        # Edge stats metrics
        metrics.append(f'firewall_edge_stats{{source="{src_ip}",target="{dst_ip}",port="{port}",metric="success_rate"}} {success_rate}')
        metrics.append(f'firewall_edge_stats{{source="{src_ip}",target="{dst_ip}",port="{port}",metric="total"}} {data["total"]}')
    
    # Return metrics in Prometheus format
    return Response('\n'.join(metrics), mimetype='text/plain')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')