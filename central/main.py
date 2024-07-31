from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ports.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

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


@app.route('/api/test/ports', methods=['GET'])
def get_ports():
    ports = Port.query.all()
    port_list = [{'id': port.id, 'port_number': port.port_number} for port in ports]
    return jsonify(port_list)

if __name__ == '__main__':
    app.run(debug=True)