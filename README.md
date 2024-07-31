# active-firewall-tester
A tool to dynamically and repeatedly testing firewall or security groups between agents on different subnets or networks.


## Status: Very Very early Alpha/PoC.

## Current Usage:

1. Stand up a single central API: 
```
 python central/main.py
 ```

 2. Run as many agents on as many hosts (or multiple on the same host on different interfaces for multi-homed or VLAN-based systems)

 ```
 python agent/agent.py eth0 http://central-ip:5000
 ```

 3. Agents will collect list of other agents IP's from the central API, try to connect to them and report back. You can specify ports (globally) using the UI for the central API at http://central-ip:5000

 4. Information will be visualized on which agents can connect to which other agents in the central UI.


## API Paths
Current API paths used by the agent are:
- `/api/agent` for "registering" and polling the list of other agents (port information is also received in this JSON doc).
- `/api/results` used for the agent POST'ing the result data about reachability of other agents on each of the specified ports.

## Docker Agent
Currently useful for testing, Interface and API endpoint can be passed in the following ENV variables:
```
AFT_NET_IFACE
AFT_API_URL
```

### Similar work.
After demoing this to someone, I was reminded of https://github.com/trustedsec/egressbuster. Great tool (also client/server) for a different usecase of testing holes in outbound firewalls or filtering.