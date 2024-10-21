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
import tempfile
import configparser
from collections import deque
from typing import Optional, Dict, Any
import struct

import zmq
from lxml import etree
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.serialization.pkcs12
import xml.sax.saxutils

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
        self.last_update_time = time.time()

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
        self.last_update_time = time.time()

    def to_cot_xml(self, stale_offset: Optional[float] = None) -> bytes:
        """Converts the drone's telemetry data to a Cursor-on-Target (CoT) XML message."""
        current_time = datetime.datetime.utcnow()
        if stale_offset is not None:
            stale_time = current_time + datetime.timedelta(seconds=stale_offset)
        else:
            stale_time = current_time + datetime.timedelta(minutes=10)

        event = etree.Element(
            'event',
            version='2.0',
            uid=self.id,
            type='b-m-p-s-m',
            time=current_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            start=current_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            stale=stale_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
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

    def __init__(
        self,
        serial_number: str,
        lat: float,
        lon: float,
        alt: float,
        cpu_usage: float = 0.0,
        memory_total: float = 0.0,
        memory_available: float = 0.0,
        disk_total: float = 0.0,
        disk_used: float = 0.0,
        temperature: float = 0.0,
        uptime: float = 0.0,
    ):
        self.id = f"wardragon-{serial_number}"
        self.lat = lat
        self.lon = lon
        self.alt = alt
        self.cpu_usage = cpu_usage
        self.memory_total = memory_total
        self.memory_available = memory_available
        self.disk_total = disk_total
        self.disk_used = disk_used
        self.temperature = temperature
        self.uptime = uptime
        self.last_update_time = time.time()

    def to_cot_xml(self) -> bytes:
        """Converts the system status data to a CoT XML message."""
        current_time = datetime.datetime.utcnow()
        stale_time = current_time + datetime.timedelta(minutes=10)

        event = etree.Element(
            'event',
            version='2.0',
            uid=self.id,
            type='b-m-p-s-m',  # Changed to match Drone class
            time=current_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            start=current_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            stale=stale_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
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

        # Format remarks with system statistics
        remarks_text = (
            f"CPU Usage: {self.cpu_usage}%, "
            f"Memory Total: {self.memory_total:.2f} MB, Memory Available: {self.memory_available:.2f} MB, "
            f"Disk Total: {self.disk_total:.2f} MB, Disk Used: {self.disk_used:.2f} MB, "
            f"Temperature: {self.temperature}°C, "
            f"Uptime: {self.uptime} seconds"
        )

        # Escape special characters
        remarks_text = xml.sax.saxutils.escape(remarks_text)

        etree.SubElement(detail, 'remarks').text = remarks_text

        etree.SubElement(detail, 'color', argb='-256')

        # Include usericon
        etree.SubElement(
            detail,
            'usericon',
            iconsetpath='34ae1613-9645-4222-a9d2-e5f243dea2865/Military/Ground_Vehicle.png'  # Use appropriate icon
        )

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
            if self.sock:
                self.sock.sendall(cot_xml)
                logger.debug(f"Sent CoT message: {cot_xml}")
            else:
                logger.error("No socket available to send CoT message.")
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


def parse_float(value, default=0.0) -> float:
    """Safely converts a value to a float, returning default if conversion fails."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


class DroneManager:
    """Manages a collection of drones and handles their updates."""

    def __init__(self, max_drones=30, rate_limit=1.0, inactivity_timeout=60.0):
        self.drones = deque(maxlen=max_drones)
        self.drone_dict = {}
        self.rate_limit = rate_limit
        self.inactivity_timeout = inactivity_timeout
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
            drones_to_remove = []
            for drone_id in list(self.drones):
                drone = self.drone_dict[drone_id]
                time_since_update = current_time - drone.last_update_time
                if time_since_update > self.inactivity_timeout:
                    # Drone is inactive, send a final CoT message with stale time set to now
                    cot_xml = drone.to_cot_xml(stale_offset=0)  # Set stale time to current time
                    self.send_cot_message(cot_xml, tak_client, tak_host, tak_port, enable_multicast, multicast_address, multicast_port)
                    drones_to_remove.append(drone_id)
                    logger.debug(f"Drone {drone_id} is inactive for {time_since_update:.2f} seconds. Sent final CoT message and removing from tracking.")
                    continue  # Skip sending regular CoT message for inactive drones

                # Update the 'stale' time in CoT message to reflect inactivity timeout
                cot_xml = drone.to_cot_xml(stale_offset=self.inactivity_timeout - time_since_update)
                self.send_cot_message(cot_xml, tak_client, tak_host, tak_port, enable_multicast, multicast_address, multicast_port)

            # Remove inactive drones
            for drone_id in drones_to_remove:
                self.drones.remove(drone_id)
                del self.drone_dict[drone_id]

            self.last_sent_time = current_time

    def send_cot_message(self, cot_xml: bytes, tak_client: Optional[TAKClient], tak_host: Optional[str], tak_port: Optional[int],
                         enable_multicast: bool, multicast_address: Optional[str], multicast_port: Optional[int]):
        """Helper method to send CoT messages to TAK client or multicast address."""
        if tak_client:
            tak_client.send(cot_xml)
        elif tak_host and tak_port:
            send_to_tak_udp(cot_xml, tak_host, tak_port)

        if enable_multicast and multicast_address and multicast_port:
            send_to_tak_udp_multicast(cot_xml, multicast_address, multicast_port)


def zmq_to_cot(zmq_host: str, zmq_port: int, zmq_status_port: Optional[int], tak_host: Optional[str] = None,
               tak_port: Optional[int] = None, tak_tls_context: Optional[ssl.SSLContext] = None,
               multicast_address: Optional[str] = None, multicast_port: Optional[int] = None,
               enable_multicast: bool = False, rate_limit: float = 1.0, max_drones: int = 30, inactivity_timeout: float = 60.0):
    """Main function to convert ZMQ messages to CoT and send to TAK server."""

    context = zmq.Context()
    telemetry_socket = context.socket(zmq.SUB)
    telemetry_socket.connect(f"tcp://{zmq_host}:{zmq_port}")
    telemetry_socket.setsockopt_string(zmq.SUBSCRIBE, "")
    logger.debug(f"Connected to telemetry ZMQ socket at tcp://{zmq_host}:{zmq_port}")

    # Only create and connect the status_socket if zmq_status_port is provided
    if zmq_status_port:
        status_socket = context.socket(zmq.SUB)
        status_socket.connect(f"tcp://{zmq_host}:{zmq_status_port}")
        status_socket.setsockopt_string(zmq.SUBSCRIBE, "")
        logger.debug(f"Connected to status ZMQ socket at tcp://{zmq_host}:{zmq_status_port}")
    else:
        status_socket = None
        logger.debug("No ZMQ status port provided. Skipping status socket setup.")

    drone_manager = DroneManager(max_drones=max_drones, rate_limit=rate_limit, inactivity_timeout=inactivity_timeout)

    # Initialize tak_client only if both tak_host and tak_port are valid
    if tak_host and tak_port:
        tak_client = TAKClient(tak_host, tak_port, tak_tls_context)
    else:
        tak_client = None

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
    if status_socket:
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
                        drone_info['lat'] = parse_float(item['Location/Vector Message'].get('latitude', 0.0))
                        drone_info['lon'] = parse_float(item['Location/Vector Message'].get('longitude', 0.0))
                        drone_info['speed'] = parse_float(item['Location/Vector Message'].get('speed', 0.0))
                        drone_info['vspeed'] = parse_float(item['Location/Vector Message'].get('vert_speed', 0.0))
                        drone_info['alt'] = parse_float(item['Location/Vector Message'].get('geodetic_altitude', 0.0))
                        drone_info['height'] = parse_float(item['Location/Vector Message'].get('height_agl', 0.0))

                    if 'Self-ID Message' in item:
                        drone_info['description'] = item['Self-ID Message'].get('text', "")

                    if 'System Message' in item:
                        drone_info['pilot_lat'] = parse_float(item['System Message'].get('latitude', 0.0))
                        drone_info['pilot_lon'] = parse_float(item['System Message'].get('longitude', 0.0))

                if 'id' in drone_info:
                    drone_id = drone_info['id']
                    if drone_id in drone_manager.drone_dict:
                        drone = drone_manager.drone_dict[drone_id]
                        drone.update(
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
                    else:
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

            if status_socket and status_socket in socks and socks[status_socket] == zmq.POLLIN:
                logger.debug("Received a message on the status socket")
                status_message = status_socket.recv_json()
                logger.debug(f"Received system status JSON: {status_message}")

                serial_number = status_message.get('serial_number', 'unknown')
                gps_data = status_message.get('gps_data', {})
                lat = parse_float(gps_data.get('latitude', 0.0))
                lon = parse_float(gps_data.get('longitude', 0.0))
                alt = parse_float(gps_data.get('altitude', 0.0))

                system_stats = status_message.get('system_stats', {})

                # Extract system statistics with defaults
                cpu_usage = parse_float(system_stats.get('cpu_usage', 0.0))
                memory = system_stats.get('memory', {})
                memory_total = parse_float(memory.get('total', 0.0)) / (1024 * 1024)  # Convert bytes to MB
                memory_available = parse_float(memory.get('available', 0.0)) / (1024 * 1024)
                disk = system_stats.get('disk', {})
                disk_total = parse_float(disk.get('total', 0.0)) / (1024 * 1024)  # Convert bytes to MB
                disk_used = parse_float(disk.get('used', 0.0)) / (1024 * 1024)
                temperature = parse_float(system_stats.get('temperature', 0.0))
                uptime = parse_float(system_stats.get('uptime', 0.0))

                if lat == 0.0 and lon == 0.0:
                    logger.warning("Latitude and longitude are missing or zero. Skipping CoT message.")
                    continue  # Skip this iteration

                system_status = SystemStatus(
                    serial_number=serial_number,
                    lat=lat,
                    lon=lon,
                    alt=alt,
                    cpu_usage=cpu_usage,
                    memory_total=memory_total,
                    memory_available=memory_available,
                    disk_total=disk_total,
                    disk_used=disk_used,
                    temperature=temperature,
                    uptime=uptime
                )

                cot_xml = system_status.to_cot_xml()

                # Sending CoT message
                if tak_client:
                    tak_client.send(cot_xml)
                elif tak_host and tak_port:
                    send_to_tak_udp(cot_xml, tak_host, tak_port)
                elif enable_multicast and multicast_address and multicast_port:
                    send_to_tak_udp_multicast(cot_xml, multicast_address, multicast_port)
                else:
                    logger.debug("No TAK host/port or multicast address/port provided. Skipping sending CoT message.")

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


def get_str(value):
    """Returns the stripped string if not empty, else None."""
    if value is not None:
        value = value.strip()
        if value:
            return value
    return None


def get_int(value, default=None):
    """Safely converts a value to an integer, returning default if conversion fails."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def get_float(value, default=None):
    """Safely converts a value to a float, returning default if conversion fails."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def get_bool(value, default=False):
    """Safely converts a value to a boolean."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ('true', 'yes', '1')
    return default


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZMQ to CoT converter.")
    parser.add_argument("--config", type=str, help="Path to config file")
    parser.add_argument("--zmq-host", help="ZMQ server host")
    parser.add_argument("--zmq-port", type=int, help="ZMQ server port for telemetry")
    parser.add_argument("--zmq-status-port", type=int, help="ZMQ server port for system status")
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
    parser.add_argument("--inactivity-timeout", type=float, help="Time in seconds before a drone is considered inactive")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    # Load config file if provided
    config_values = {}
    if args.config:
        config_values = load_config(args.config)

    setup_logging(args.debug)
    logger.info("Starting ZMQ to CoT converter with log level: %s", "DEBUG" if args.debug else "INFO")

    # Assign configuration values, giving precedence to command-line arguments
    zmq_host = args.zmq_host if args.zmq_host is not None else get_str(config_values.get("zmq_host", "127.0.0.1"))
    zmq_port = args.zmq_port if args.zmq_port is not None else get_int(config_values.get("zmq_port"), 4224)
    zmq_status_port = args.zmq_status_port if args.zmq_status_port is not None else get_int(config_values.get("zmq_status_port"), None)

    tak_host = args.tak_host if args.tak_host is not None else get_str(config_values.get("tak_host"))
    tak_port = args.tak_port if args.tak_port is not None else get_int(config_values.get("tak_port"), None)

    tak_tls_p12 = args.tak_tls_p12 if args.tak_tls_p12 is not None else get_str(config_values.get("tak_tls_p12"))
    tak_tls_p12_pass = args.tak_tls_p12_pass if args.tak_tls_p12_pass is not None else get_str(config_values.get("tak_tls_p12_pass"))
    tak_tls_skip_verify = args.tak_tls_skip_verify if args.tak_tls_skip_verify else get_bool(config_values.get("tak_tls_skip_verify"), False)

    tak_multicast_addr = args.tak_multicast_addr if args.tak_multicast_addr is not None else get_str(config_values.get("tak_multicast_addr"))
    tak_multicast_port = args.tak_multicast_port if args.tak_multicast_port is not None else get_int(config_values.get("tak_multicast_port"), None)
    enable_multicast = args.enable_multicast or get_bool(config_values.get("enable_multicast"), False)

    rate_limit = args.rate_limit if args.rate_limit is not None else get_float(config_values.get("rate_limit", 1.0))
    max_drones = args.max_drones if args.max_drones is not None else get_int(config_values.get("max_drones", 30))
    inactivity_timeout = args.inactivity_timeout if args.inactivity_timeout is not None else get_float(config_values.get("inactivity_timeout", 60.0))

    tak_tls_context = None

    if tak_tls_p12:
        try:
            with open(tak_tls_p12, 'rb') as p12_file:
                p12_data = p12_file.read()
        except OSError as err:
            logger.critical("Failed to read TAK server TLS PKCS#12 file: %s.", err)
            exit(1)

        p12_pass = None
        pem_encryption = cryptography.hazmat.primitives.serialization.NoEncryption()
        if tak_tls_p12_pass:
            p12_pass = tak_tls_p12_pass.encode()
            pem_encryption = cryptography.hazmat.primitives.serialization.BestAvailableEncryption(p12_pass)

        try:
            key, cert, more_certs = cryptography.hazmat.primitives.serialization.pkcs12.load_key_and_certificates(p12_data, p12_pass)
        except Exception as err:
            logger.critical("Failed to load TAK server TLS PKCS#12: %s.", err)
            exit(1)

        key_bytes = key.private_bytes(
            cryptography.hazmat.primitives.serialization.Encoding.PEM,
            cryptography.hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL,
            pem_encryption
        )
        cert_bytes = cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM)
        ca_bytes = b"".join(
            cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM) for cert in more_certs
        )

        with tempfile.NamedTemporaryFile(delete=False) as key_file, \
                tempfile.NamedTemporaryFile(delete=False) as cert_file, \
                tempfile.NamedTemporaryFile(delete=False) as ca_file:
            key_file.write(key_bytes)
            cert_file.write(cert_bytes)
            ca_file.write(ca_bytes)

        tak_tls_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        tak_tls_context.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name, password=p12_pass)
        if len(ca_bytes) > 0:
            tak_tls_context.load_verify_locations(cafile=ca_file.name)
        if tak_tls_skip_verify:
            tak_tls_context.check_hostname = False
            tak_tls_context.verify_mode = ssl.CERT_NONE

    zmq_to_cot(zmq_host, zmq_port, zmq_status_port, tak_host, tak_port, tak_tls_context, tak_multicast_addr,
               tak_multicast_port, enable_multicast, rate_limit, max_drones, inactivity_timeout)
