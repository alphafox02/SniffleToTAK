"""
MIT License

Copyright (c) 2024 cemaxecuter

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


import argparse
import json
import psutil
import subprocess
import time
import zmq
import signal
import sys
import uuid
import os  # Import os module
from gps import gps, WATCH_ENABLE, WATCH_NEWSTYLE


def get_gps_data(debug=False):
    """Retrieve GPS data from gpsd."""
    try:
        gpsd = gps(mode=WATCH_ENABLE | WATCH_NEWSTYLE)

        if debug:
            print("Waiting for GPS data...")

        report = gpsd.next()
        while report['class'] != 'TPV':
            report = gpsd.next()

        gps_info = {
            'latitude': getattr(report, 'lat', 'N/A'),
            'longitude': getattr(report, 'lon', 'N/A'),
            'altitude': getattr(report, 'alt', 'N/A'),
            'speed': getattr(report, 'speed', 'N/A')
        }
        if debug:
            print(f"Received GPS data: {gps_info}")
        return gps_info

    except KeyError as e:
        if debug:
            print(f"Missing GPS data key: {e}")
    except StopIteration:
        if debug:
            print("No GPS data available.")
    except Exception as e:
        if debug:
            print(f"Error connecting to gpsd: {e}")

    return {'latitude': 'N/A', 'longitude': 'N/A', 'altitude': 'N/A', 'speed': 'N/A'}


def get_serial_number(debug=False):
    """Retrieve the system's serial number or MAC address as a unique identifier."""
    invalid_serials = [
        'N/A', 'Default string', 'To be filled by O.E.M.', 'None', 'Not Specified', 'Unknown', ''
    ]
    try:
        result = subprocess.run(
            ['sudo', 'dmidecode', '-t', 'system'],
            capture_output=True, text=True, check=True
        )
        output = result.stdout
        serial_number = None
        for line in output.split('\n'):
            if 'Serial Number:' in line:
                serial_number = line.split(':')[-1].strip()
                break

        if serial_number and serial_number not in invalid_serials:
            if debug:
                print(f"Using serial number: {serial_number}")
            return serial_number

    except subprocess.CalledProcessError as e:
        if debug:
            print(f"Error retrieving serial number: {e}")

    except Exception as e:
        if debug:
            print(f"Unexpected error retrieving serial number: {e}")

    # If serial number is invalid or not found, try to get MAC address
    try:
        mac_address = None
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == psutil.AF_LINK:
                    if interface.startswith(('eth', 'en', 'wlan')):
                        mac_address = addr.address.replace(':', '').lower()
                        if mac_address and mac_address != '000000000000':
                            if debug:
                                print(f"Using MAC address from interface {interface} as UID: {mac_address}")
                            return mac_address
        # If no MAC address found, generate UUID and store it
        uid_file = '/var/tmp/system_uid.txt'
        if os.path.exists(uid_file):
            with open(uid_file, 'r') as f:
                saved_uuid = f.read().strip()
                if debug:
                    print(f"Using saved UUID: {saved_uuid}")
                return saved_uuid
        else:
            generated_uuid = str(uuid.uuid4())
            with open(uid_file, 'w') as f:
                f.write(generated_uuid)
            if debug:
                print(f"No serial number or MAC address found. Generated and saved UUID: {generated_uuid}")
            return generated_uuid
    except Exception as e:
        if debug:
            print(f"Error retrieving MAC address: {e}")
        # Generate UUID and store it
        uid_file = '/var/tmp/system_uid.txt'
        if os.path.exists(uid_file):
            with open(uid_file, 'r') as f:
                saved_uuid = f.read().strip()
                if debug:
                    print(f"Using saved UUID: {saved_uuid}")
                return saved_uuid
        else:
            generated_uuid = str(uuid.uuid4())
            with open(uid_file, 'w') as f:
                f.write(generated_uuid)
            if debug:
                print(f"Generated and saved UUID: {generated_uuid}")
            return generated_uuid


def get_cpu_temperature():
    """Retrieve the CPU temperature using the 'sensors' command."""
    try:
        result = subprocess.run(['sensors'], capture_output=True, text=True, check=True)
        for line in result.stdout.splitlines():
            if 'Package id 0:' in line:
                temp_str = line.split('+')[1].split('°')[0].strip()
                return float(temp_str)
    except Exception as e:
        if debug:
            print(f"Error retrieving CPU temperature: {e}")
    return 'N/A'


def get_system_stats():
    """Gather system statistics using psutil."""
    return {
        'cpu_usage': psutil.cpu_percent(),
        'memory': psutil.virtual_memory()._asdict(),
        'disk': psutil.disk_usage('/')._asdict(),
        'temperature': get_cpu_temperature(),
        'uptime': time.time() - psutil.boot_time()
    }


def create_zmq_context(host, port):
    """Create and bind a ZMQ PUB socket."""
    context = zmq.Context()
    socket = context.socket(zmq.PUB)
    try:
        socket.bind(f"tcp://{host}:{port}")
    except zmq.ZMQError as e:
        print(f"Error binding ZMQ socket: {e}")
        sys.exit(1)  # Exit if socket binding fails
    return socket


def signal_handler(sig, frame):
    """Handle SIGINT/SIGTERM signals for graceful exit."""
    print("Exiting... Closing resources.")
    sys.exit(0)


def main(host, port, interval, debug):
    """Main function to gather data and send it over ZMQ."""
    # Set up signal handling for graceful exit
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    socket = create_zmq_context(host, port) if not debug else None

    while True:
        try:
            data = {
                'timestamp': time.time(),
                'gps_data': get_gps_data(debug=debug),
                'serial_number': get_serial_number(debug=debug),
                'system_stats': get_system_stats()
            }
            json_data = json.dumps(data, indent=4)

            if debug:
                print(f"Debug Output:\n{json_data}")
            else:
                socket.send_string(json_data)

            time.sleep(interval)

        except zmq.ZMQError as e:
            if debug:
                print(f"ZMQ Error: {e}")
            time.sleep(5)  # Backoff before retrying

        except Exception as e:
            if debug:
                print(f"Unexpected error: {e}")
            time.sleep(5)  # Backoff before retrying


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WarDragon System Monitor")
    parser.add_argument('--zmq_host', type=str, default='0.0.0.0', help='ZMQ Host')
    parser.add_argument('--zmq_port', type=int, default=4225, help='ZMQ Port')
    parser.add_argument('--interval', type=int, default=30, help='Update interval in seconds')
    parser.add_argument('-d', '--debug', action='store_true', help='Print JSON to terminal for debugging')

    args = parser.parse_args()
    main(args.zmq_host, args.zmq_port, args.interval, args.debug)
