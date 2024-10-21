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


import sys
import ssl
import socket
import signal
import logging
import argparse
import datetime
import time
import configparser
from collections import deque
from typing import Optional, Dict, Any
import struct

import zmq
from lxml import etree
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.serialization.pkcs12

# Setup logging
logger = logging.getLogger(__name__)

class Drone:
    """Represents a drone and its telemetry data."""

    def __init__(self, id: str, lat: float, lon: float, speed: float, vspeed: float,
                 alt: float, height: float, pilot_lat: float, pilot_lon: float, description: str):
        self.id = id
        self.lat = lat
        self.lon = lon
        self.speed = speed
        self.vspeed = vspeed
        self.alt = alt
        self.height = height
        self.pilot_lat = pilot_lat
        self.pilot_lon = pilot_lon
        self.description = description

    def update(self, lat: float, lon: float, speed: float, vspeed: float, alt: float,
               height: float, pilot_lat: float, pilot_lon: float, description: str):
        """Updates the drone's telemetry data."""
        self.lat = lat
        self.lon = lon
        self.speed = speed
        self.vspeed = vspeed
        self.alt = alt
        self.height = height
        self.pilot_lat = pilot_lat
        self.pilot_lon = pilot_lon
        self.description = description

    def to_cot_xml(self) -> bytes:
        """Converts the drone's telemetry data to a Cursor-on-Target (CoT) XML message."""
        event = etree.Element(
            'event',
            version='2.0',
            uid=self.id,
            type='b-m-p-s-m',
            time=datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            start=datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            stale=(datetime.datetime.utcnow() + datetime.timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            how='m-g'
        )

        point = etree.SubElement(
            event,
            'point',
            lat=str(self.lat),
            lon=str(self.lon),
            hae=str(self.alt),
            ce='35.0',
            le='999999'
        )

        detail = etree.SubElement(event, 'detail')

        etree.SubElement(detail, 'contact', endpoint='', phone='', callsign=self.id)

        etree.SubElement(detail, 'precisionlocation', geopointsrc='gps', altsrc='gps')

        remarks_text = (
            f"Description: {self.description}, Speed: {self.speed} m/s, VSpeed: {self.vspeed} m/s, "
            f"Altitude: {self.alt} m, Height: {self.height} m, "
            f"Pilot Lat: {self.pilot_lat}, Pilot Lon: {self.pilot_lon}"
        )
        etree.SubElement(detail, 'remarks').text = remarks_text

        etree.SubElement(detail, 'color', argb='-256')

        etree.SubElement(
            detail,
            'usericon',
            iconsetpath='34ae1613-9645-4222-a9d2-e5f243dea2865/Military/UAV_quad.png'
        )

        return etree.tostring(event, pretty_print=True, xml_declaration=True, encoding='UTF-8')


class SystemStatus:
    """Represents system status data."""

    def __init__(self, serial_number: str, lat: float, lon: float, alt: float, remarks: str):
        self.id = f"system-{serial_number}"
        self.lat = lat
        self.lon = lon
        self.alt = alt
        self.remarks = remarks

    def to_cot_xml(self) -> bytes:
        """Converts the system status data to a CoT XML message."""
        event = etree.Element(
            'event',
            version='2.0',
            uid=self.id,
            type='b-m-p-s-m',  # Friendly Ground Unit
            time=datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            start=datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            stale=(datetime.datetime.utcnow() + datetime.timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            how='m-g'
        )

        point = etree.SubElement(
            event,
            'point',
            lat=str(self.lat),
            lon=str(self.lon),
            hae=str(self.alt),
            ce='35.0',
            le='999999'
        )

        detail = etree.SubElement(event, 'detail')

        # Include contact information
        etree.SubElement(detail, 'contact', endpoint='', phone='', callsign=self.id)

        # Include precision location
        etree.SubElement(detail, 'precisionlocation', geopointsrc='gps', altsrc='gps')

         # Include remarks without CDATA
        remarks_element = etree.SubElement(detail, 'remarks')
        # Clean the remarks text to ensure it's XML-safe
        safe_remarks = etree.CDATA(self.remarks)
        remarks_element.text = safe_remarks

        # Include color (optional)
        etree.SubElement(detail, 'color', argb='-1')  # White color

        # Omit usericon to use the default dot icon
        # Alternatively, specify a default icon if needed
        # etree.SubElement(detail, 'usericon', iconsetpath='some/default/icon/path')

        return etree.tostring(event, pretty_print=True, xml_declaration=True, encoding='UTF-8')
        
class TAKClient:
    """Client for connecting to a TAK server using TLS and sending CoT messages."""
    
    def __init__(self, tak_host: str, tak_port: int, tak_tls_context: Optional[ssl.SSLContext]):
        self.tak_host = tak_host
        self.tak_port = tak_port
        self.tak_tls_context = tak_tls_context
        self.sock = None

    def connect(self):
        """Establishes a connection to the TAK server."""
        try:
            self.sock = socket.create_connection((self.tak_host, self.tak_port))
            if self.tak_tls_context:
                self.sock = self.tak_tls_context.wrap_socket(self.sock, server_hostname=self.tak_host)
            logger.debug("Connected to TAK server")
        except Exception as e:
            logger.error(f"Error connecting to TAK server: {e}")
            self.sock = None

    def send(self, cot_xml: bytes):
        """Sends a CoT XML message to the TAK server."""
        try:
            if not self.sock:
                self.connect()
            self.sock.sendall(cot_xml)
            logger.debug(f"Sent CoT message: {cot_xml}")
        except Exception as e:
            logger.error(f"Error sending CoT message: {e}")
            self.close()
            self.connect()

    def close(self):
        """Closes the connection to the TAK server."""
        if self.sock:
            self.sock.close()
            self.sock = None
            logger.debug("Closed connection to TAK server")

def send_to_tak_udp(cot_xml: bytes, tak_host: str, tak_port: int):
    """Sends a CoT XML message to the TAK server via UDP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(cot_xml, (tak_host, tak_port))
        sock.close()
        logger.debug(f"Sent CoT message via UDP: {cot_xml}")
    except Exception as e:
        logger.error(f"Error sending CoT message via UDP: {e}")

def send_to_tak_udp_multicast(cot_xml: bytes, multicast_address: str, multicast_port: int):
    """Sends a CoT XML message to a multicast address via UDP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        ttl = struct.pack('b', 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
        sock.sendto(cot_xml, (multicast_address, multicast_port))
        sock.close()
        logger.debug(f"Sent CoT message via multicast: {cot_xml}")
    except Exception as e:
        logger.error(f"Error sending CoT message via multicast: {e}")

def parse_float(value) -> float:
    """Parses a value to a float, handling different data types."""
    try:
        if isinstance(value, (float, int)):
            return float(value)
        return float(str(value).strip())
    except (ValueError, TypeError):
        return 0.0

class DroneManager:
    """Manages a collection of drones and handles their updates."""

    def __init__(self, max_drones=30, rate_limit=1.0):
        self.drones = deque(maxlen=max_drones)
        self.drone_dict = {}
        self.rate_limit = rate_limit
        self.last_sent_time = 0.0

    def update_or_add_drone(self, drone_id, drone_data):
        """Updates an existing drone or adds a new one to the collection."""
        if drone_id not in self.drone_dict:
            if len(self.drones) >= self.drones.maxlen:
                oldest_drone_id = self.drones.popleft()
                del self.drone_dict[oldest_drone_id]
            self.drones.append(drone_id)
            self.drone_dict[drone_id] = drone_data
        else:
            self.drone_dict[drone_id] = drone_data

    def send_updates(self, tak_client: Optional[TAKClient], tak_host: Optional[str], tak_port: Optional[int],
                     enable_multicast: bool, multicast_address: Optional[str], multicast_port: Optional[int]):
        """Sends updates to the TAK server or multicast address."""
        current_time = time.time()
        if current_time - self.last_sent_time >= self.rate_limit:
            for drone_id in self.drones:
                cot_xml = self.drone_dict[drone_id].to_cot_xml()

                if tak_client:
                    tak_client.send(cot_xml)
                elif tak_host and tak_port:
                    send_to_tak_udp(cot_xml, tak_host, tak_port)

                if enable_multicast and multicast_address and multicast_port:
                    send_to_tak_udp_multicast(cot_xml, multicast_address, multicast_port)

            self.last_sent_time = current_time

def zmq_to_cot(zmq_host: str, zmq_port: int, zmq_status_port: int, tak_host: Optional[str] = None,
               tak_port: Optional[int] = None, tak_tls_context: Optional[ssl.SSLContext] = None,
               multicast_address: Optional[str] = None, multicast_port: Optional[int] = None,
               enable_multicast: bool = False, rate_limit: float = 1.0, max_drones: int = 30):
    """Main function to convert ZMQ messages to CoT and send to TAK server."""

    context = zmq.Context()
    telemetry_socket = context.socket(zmq.SUB)
    telemetry_socket.connect(f"tcp://{zmq_host}:{zmq_port}")
    telemetry_socket.setsockopt_string(zmq.SUBSCRIBE, "")
    logger.debug(f"Connected to telemetry ZMQ socket at tcp://{zmq_host}:{zmq_port}")

    status_socket = context.socket(zmq.SUB)
    status_socket.connect(f"tcp://{zmq_host}:{zmq_status_port}")
    status_socket.setsockopt_string(zmq.SUBSCRIBE, "")
    logger.debug(f"Connected to status ZMQ socket at tcp://{zmq_host}:{zmq_status_port}")

    drone_manager = DroneManager(max_drones=max_drones, rate_limit=rate_limit)
    tak_client = TAKClient(tak_host, tak_port, tak_tls_context) if tak_host and tak_port else None

    def signal_handler(sig, frame):
        """Handles signal interruptions for graceful shutdown."""
        logger.info("Interrupted by user")
        telemetry_socket.close()
        if status_socket:
            status_socket.close()
        if not context.closed:
            context.term()
        if tak_client:
            tak_client.close()
        logger.info("Cleaned up ZMQ resources")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    poller = zmq.Poller()
    poller.register(telemetry_socket, zmq.POLLIN)
    poller.register(status_socket, zmq.POLLIN)

    try:
        while True:
            socks = dict(poller.poll(timeout=1000))
            if telemetry_socket in socks and socks[telemetry_socket] == zmq.POLLIN:
                logger.debug("Received a message on the telemetry socket")
                message = telemetry_socket.recv_json()
                logger.debug(f"Received telemetry JSON: {message}")

                drone_info = {}
                for item in message:
                    if 'Basic ID' in item:
                        id_type = item['Basic ID'].get('id_type')
                        if id_type == 'Serial Number (ANSI/CTA-2063-A)' and 'id' not in drone_info:
                            drone_info['id'] = item['Basic ID'].get('id', 'unknown')
                            logger.debug(f"Parsed Serial Number ID: {drone_info['id']}")
                        elif id_type == 'CAA Assigned Registration ID' and 'id' not in drone_info:
                            drone_info['id'] = item['Basic ID'].get('id', 'unknown')
                            logger.debug(f"Parsed CAA Assigned ID: {drone_info['id']}")

                    if 'id' in drone_info:
                        if not drone_info['id'].startswith('drone-'):
                            drone_info['id'] = f"drone-{drone_info['id']}"
                        logger.debug(f"Ensured drone id with prefix: {drone_info['id']}")

                    if 'Location/Vector Message' in item:
                        drone_info['lat'] = parse_float(item['Location/Vector Message'].get('latitude', "0.0"))
                        drone_info['lon'] = parse_float(item['Location/Vector Message'].get('longitude', "0.0"))
                        drone_info['speed'] = parse_float(item['Location/Vector Message'].get('speed', "0.0"))
                        drone_info['vspeed'] = parse_float(item['Location/Vector Message'].get('vert_speed', "0.0"))
                        drone_info['alt'] = parse_float(item['Location/Vector Message'].get('geodetic_altitude', "0.0"))
                        drone_info['height'] = parse_float(item['Location/Vector Message'].get('height_agl', "0.0"))

                    if 'Self-ID Message' in item:
                        drone_info['description'] = item['Self-ID Message'].get('text', "")

                    if 'System Message' in item:
                        drone_info['pilot_lat'] = parse_float(item['System Message'].get('latitude', "0.0"))
                        drone_info['pilot_lon'] = parse_float(item['System Message'].get('longitude', "0.0"))

                if 'id' in drone_info:
                    drone_id = drone_info['id']
                    drone = Drone(
                        id=drone_info['id'],
                        lat=drone_info.get('lat', 0.0),
                        lon=drone_info.get('lon', 0.0),
                        speed=drone_info.get('speed', 0.0),
                        vspeed=drone_info.get('vspeed', 0.0),
                        alt=drone_info.get('alt', 0.0),
                        height=drone_info.get('height', 0.0),
                        pilot_lat=drone_info.get('pilot_lat', 0.0),
                        pilot_lon=drone_info.get('pilot_lon', 0.0),
                        description=drone_info.get('description', "")
                    )
                    drone_manager.update_or_add_drone(drone_id, drone)

            if status_socket in socks and socks[status_socket] == zmq.POLLIN:
                logger.debug("Received a message on the status socket")
                status_message = status_socket.recv_json()
                logger.debug(f"Received system status JSON: {status_message}")

                serial_number = status_message.get('serial_number', 'unknown')
                gps_data = status_message.get('gps_data', {})
                lat = parse_float(gps_data.get('latitude', '0.0'))
                lon = parse_float(gps_data.get('longitude', '0.0'))
                alt = parse_float(gps_data.get('altitude', '0.0'))

                system_stats = status_message.get('system_stats', {})

                # Extract individual system statistics with labels
                cpu_usage = system_stats.get('cpu_usage', 'N/A')
                memory = system_stats.get('memory', {})
                memory_total = memory.get('total', 'N/A')
                memory_available = memory.get('available', 'N/A')
                disk = system_stats.get('disk', {})
                disk_total = disk.get('total', 'N/A')
                disk_used = disk.get('used', 'N/A')
                temperature = system_stats.get('temperature', 'N/A')
                uptime = system_stats.get('uptime', 'N/A')

                # Format the remarks with labels
                remarks = (
                    f"CPU Usage: {cpu_usage}%\n"
                    f"Memory Total: {memory_total} bytes, Available: {memory_available} bytes\n"
                    f"Disk Total: {disk_total} bytes, Used: {disk_used} bytes\n"
                    f"Temperature: {temperature}°C\n"
                    f"Uptime: {uptime} seconds"
                )

                system_status = SystemStatus(serial_number, lat, lon, alt, remarks)

                cot_xml = system_status.to_cot_xml()

                # Sending CoT message
                if tak_client:
                    tak_client.send(cot_xml)
                elif tak_host and tak_port:
                    send_to_tak_udp(cot_xml, tak_host, tak_port)
                if enable_multicast and multicast_address and multicast_port:
                    send_to_tak_udp_multicast(cot_xml, multicast_address, multicast_port)

            drone_manager.send_updates(tak_client, tak_host, tak_port, enable_multicast, multicast_address, multicast_port)

    except Exception as e:
        logger.error(f"Error in main loop: {e}")
    except KeyboardInterrupt:
        signal_handler(None, None)

def load_config(file_path: str) -> dict:
    """Load configurations from a file."""
    config = configparser.ConfigParser()
    config.read(file_path)
    config_dict = {}
    if 'SETTINGS' in config:
        config_dict.update(config['SETTINGS'])
    return config_dict

def setup_logging(debug: bool):
    """Set up logging configuration."""
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG if debug else logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)

    if not logger.handlers:
        logger.addHandler(ch)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZMQ to CoT converter.")
    parser.add_argument("--config", type=str, help="Path to config file")
    parser.add_argument("--zmq-host", help="ZMQ server host")
    parser.add_argument("--zmq-port", type=int, help="ZMQ server port for telemetry")
    parser.add_argument("--zmq-status-port", type=int, help="ZMQ server port for system status (optional)")
    parser.add_argument("--tak-host", type=str, help="TAK server hostname or IP address (optional)")
    parser.add_argument("--tak-port", type=int, help="TAK server port (optional)")
    parser.add_argument("--tak-tls-p12", type=str, help="Path to TAK server TLS PKCS#12 file (optional)")
    parser.add_argument("--tak-tls-p12-pass", type=str, help="Password for TAK server TLS PKCS#12 file (optional)")
    parser.add_argument("--tak-tls-skip-verify", action="store_true", help="(UNSAFE) Disable TLS server verification")
    parser.add_argument("--tak-multicast-addr", type=str, help="ATAK multicast address (optional)")
    parser.add_argument("--tak-multicast-port", type=int, help="ATAK multicast port (optional)")
    parser.add_argument("--enable-multicast", action="store_true", help="Enable sending to multicast address")
    parser.add_argument("--rate-limit", type=float, help="Rate limit for sending CoT messages (seconds)")
    parser.add_argument("--max-drones", type=int, help="Maximum number of drones to track simultaneously")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    # Load config file if provided
    config_values = {}
    if args.config:
        config_values = load_config(args.config)

    setup_logging(args.debug)
    logger.info("Starting ZMQ to CoT converter with log level: %s", "DEBUG" if args.debug else "INFO")

    # Function to safely get integer values from config or defaults
    def get_int(value, default=None):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    # Function to safely get boolean values from config or defaults
    def get_bool(value, default=False):
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ('true', 'yes', '1')
        return default

    # Assign configuration values, giving precedence to command-line arguments
    zmq_host = args.zmq_host if args.zmq_host is not None else config_values.get("zmq_host", "127.0.0.1")
    zmq_port = args.zmq_port if args.zmq_port is not None else get_int(config_values.get("zmq_port"), 4224)
    zmq_status_port = args.zmq_status_port if args.zmq_status_port is not None else get_int(config_values.get("zmq_status_port"), None)
    tak_host = args.tak_host if args.tak_host is not None else config_values.get("tak_host") or None
    tak_port = args.tak_port if args.tak_port is not None else get_int(config_values.get("tak_port"), None)
    tak_tls_p12 = args.tak_tls_p12 if args.tak_tls_p12 is not None else config_values.get("tak_tls_p12")
    tak_tls_p12_pass = args.tak_tls_p12_pass if args.tak_tls_p12_pass is not None else config_values.get("tak_tls_p12_pass")
    tak_tls_skip_verify = args.tak_tls_skip_verify if args.tak_tls_skip_verify else get_bool(config_values.get("tak_tls_skip_verify"), False)
    tak_multicast_addr = args.tak_multicast_addr if args.tak_multicast_addr is not None else config_values.get("tak_multicast_addr")
    tak_multicast_port = args.tak_multicast_port if args.tak_multicast_port is not None else get_int(config_values.get("tak_multicast_port"), None)
    enable_multicast = args.enable_multicast if args.enable_multicast else get_bool(config_values.get("enable_multicast"), False)
    rate_limit = args.rate_limit if args.rate_limit is not None else float(config_values.get("rate_limit", 1.0))
    max_drones = args.max_drones if args.max_drones is not None else int(config_values.get("max_drones", 30))

    setup_logging(args.debug)
    logger.info("Starting ZMQ to CoT converter with log level: %s", "DEBUG" if args.debug else "INFO")

    tak_tls_context = None
    if tak_tls_p12:
        try:
            with open(tak_tls_p12, 'rb') as p12_file:
                p12_data = p12_file.read()
        except OSError as err:
            logger.critical("Failed to read TAK server TLS PKCS#12 file: %s.", err)
            exit(1)

        p12_pass = tak_tls_p12_pass.encode() if tak_tls_p12_pass else None

        try:
            key, cert, more_certs = cryptography.hazmat.primitives.serialization.pkcs12.load_key_and_certificates(p12_data, p12_pass)
        except Exception as err:
            logger.critical("Failed to load TAK server TLS PKCS#12: %s.", err)
            exit(1)

        tak_tls_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        tak_tls_context.load_cert_chain(certfile=cert.public_bytes(encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM),
                                        keyfile=key.private_bytes(encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM,
                                                                  format=cryptography.hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL,
                                                                  encryption_algorithm=cryptography.hazmat.primitives.serialization.NoEncryption()))
        if more_certs:
            tak_tls_context.load_verify_locations(cadata=''.join([cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM).decode('utf-8') for cert in more_certs]))
        if tak_tls_skip_verify:
            tak_tls_context.check_hostname = False
            tak_tls_context.verify_mode = ssl.CERT_NONE

    zmq_to_cot(zmq_host, zmq_port, zmq_status_port, tak_host, tak_port, tak_tls_context, tak_multicast_addr,
               tak_multicast_port, enable_multicast, rate_limit, max_drones)
