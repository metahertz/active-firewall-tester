from flask import Flask, request, jsonify, render_template, redirect, url_for, send_file
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
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
    return render_template('index.html')

@app.route('/add', methods=['POST'])
def add_port():
    ports = request.form.get('ports')
    port_list = ports.split(',')
    for port in port_list:
        new_port = Port(port_number=int(port.strip()))
        db.session.add(new_port)
    db.session.commit()
    return redirect(url_for('index'))

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
    # Step 1: Extract Data
    connection_results = ConnectionResult.query.all()

    # Step 2: Create Graph
    G = nx.MultiGraph()

    for result in connection_results:
            print(f"result.ip: {result.ip}. result.port: {result.port}. result.success: {result.success}")
            if not G.has_node(result.ip):
                G.add_node(result.ip, label=f"IP: {result.ip}")
            if not G.has_node(result.agent_ip):
                G.add_node(result.agent_ip, label=f"IP: {result.ip} Agent: {result.agent_uuid}")
            G.add_edge(result.agent_ip, result.ip, port=result.port, weight=result.port, success=result.success, edge_labels=result.port)
        
    # Step 3: Visualize Graph
    pos = nx.spring_layout(G)  # positions for all nodes

    # Draw nodes
    nx.draw_networkx_nodes(G, pos, node_size=700)

    # Draw edges
    nx.draw_networkx_edges(G, pos, width=2, )

    # Draw labels
    nx.draw_networkx_labels(G, pos, font_size=12, font_family='sans-serif')

    # Draw edge labels (ports)
    edge_labels = {(u, v, k): d['port'] for u, v, k, d in G.edges(data=True, keys=True)}
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)
    # Save plot to a BytesIO object
    img = BytesIO()
    plt.title('Agent-UUID and IP Connections with Ports')
    plt.savefig(img, format='png')
    img.seek(0)
    plt.close()

    return send_file(img, mimetype='image/png')

@app.route('/api/test/ports', methods=['GET'])
def get_ports():
    ports = Port.query.all()
    port_list = [{'id': port.id, 'port_number': port.port_number} for port in ports]
    return jsonify(port_list)

if __name__ == '__main__':
    app.run(debug=True)