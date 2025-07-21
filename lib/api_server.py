import flask
import os
import signal

app = flask.Flask(__name__)

# In-memory dictionary to store SOCKS port to PID mappings
tor_pids = {}

@app.route('/pause/<int:socks_port>', methods=['POST'])
def pause_tor_instance(socks_port):
    """
    Pauses a Tor instance by sending a SIGSTOP signal.
    """
    if socks_port in tor_pids:
        pid = tor_pids[socks_port]
        try:
            os.kill(pid, signal.SIGSTOP)
            return flask.jsonify({'status': 'success', 'message': f'Paused Tor instance with PID {pid}'}), 200
        except ProcessLookupError:
            return flask.jsonify({'status': 'error', 'message': f'Process with PID {pid} not found'}), 404
        except Exception as e:
            return flask.jsonify({'status': 'error', 'message': str(e)}), 500
    else:
        return flask.jsonify({'status': 'error', 'message': f'SOCKS port {socks_port} not found'}), 404

@app.route('/resume/<int:socks_port>', methods=['POST'])
def resume_tor_instance(socks_port):
    """
    Resumes a Tor instance by sending a SIGCONT signal.
    """
    if socks_port in tor_pids:
        pid = tor_pids[socks_port]
        try:
            os.kill(pid, signal.SIGCONT)
            return flask.jsonify({'status': 'success', 'message': f'Resumed Tor instance with PID {pid}'}), 200
        except ProcessLookupError:
            return flask.jsonify({'status': 'error', 'message': f'Process with PID {pid} not found'}), 404
        except Exception as e:
            return flask.jsonify({'status': 'error', 'message': str(e)}), 500
    else:
        return flask.jsonify({'status': 'error', 'message': f'SOCKS port {socks_port} not found'}), 404

@app.route('/pid/<int:socks_port>', methods=['GET'])
def get_pid(socks_port):
    """
    Returns the PID of a Tor instance.
    """
    if socks_port in tor_pids:
        return flask.jsonify({'pid': tor_pids[socks_port]}), 200
    else:
        return flask.jsonify({'status': 'error', 'message': f'SOCKS port {socks_port} not found'}), 404

@app.route('/pause_all_except', methods=['POST'])
def pause_all_except():
    """
    Pauses all Tor instances except those in the provided list of top proxies.
    Expects a JSON payload with a 'top_proxies' key, which is a list of SOCKS ports.
    """
    data = flask.request.get_json()
    if not data or 'top_proxies' not in data:
        return flask.jsonify({'status': 'error', 'message': 'Missing top_proxies in request body'}), 400

    top_proxies = data['top_proxies']
    paused_ports = []
    errors = []

    for socks_port, pid in tor_pids.items():
        if socks_port not in top_proxies:
            try:
                os.kill(pid, signal.SIGSTOP)
                paused_ports.append(socks_port)
            except Exception as e:
                errors.append({socks_port: str(e)})

    return flask.jsonify({'status': 'success', 'paused_ports': paused_ports, 'errors': errors}), 200

@app.route('/resume_all', methods=['POST'])
def resume_all():
    """
    Resumes all paused Tor instances.
    """
    resumed_ports = []
    errors = []

    for socks_port, pid in tor_pids.items():
        try:
            os.kill(pid, signal.SIGCONT)
            resumed_ports.append(socks_port)
        except Exception as e:
            errors.append({socks_port: str(e)})

    return flask.jsonify({'status': 'success', 'resumed_ports': resumed_ports, 'errors': errors}), 200

@app.route('/update_pid', methods=['POST'])
def update_pid():
    """
    Updates the PID for a given SOCKS port.
    Expects a JSON payload with 'socks_port' and 'pid' keys.
    """
    data = flask.request.get_json()
    if not data or 'socks_port' not in data or 'pid' not in data:
        return flask.jsonify({'status': 'error', 'message': 'Missing socks_port or pid in request body'}), 400

    socks_port = data['socks_port']
    pid = data['pid']
    tor_pids[socks_port] = pid
    return flask.jsonify({'status': 'success', 'message': f'PID for SOCKS port {socks_port} updated to {pid}'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
