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
import tempfile
import time
from collections import deque
from typing import Optional

import zmq
from lxml import etree
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.serialization.pkcs12

# Setup logging
logger = logging.getLogger(__name__)

class Drone:
    """A class representing a drone and its telemetry data."""
    def __init__(self, id: str, lat: float, lon: float, speed: float, vspeed: float, alt: float, height: float, pilot_lat: float, pilot_lon: float, description: str):
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

    def update(self, lat: float, lon: float, speed: float, vspeed: float, alt: float, height: float, pilot_lat: float, pilot_lon: float, description: str):
        """Update the drone's telemetry data."""
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
        """Convert the drone's telemetry data to a Cursor-on-Target (CoT) XML message."""
        event = etree.Element('event')
        event.set('version', '2.0')
        event.set('uid', f"drone-{self.id}")
        event.set('type', 'b-m-p-s-m')
        event.set('time', datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ'))
        event.set('start', datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ'))
        event.set('stale', (datetime.datetime.utcnow() + datetime.timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%S.%fZ'))
        event.set('how', 'm-g')

        point = etree.SubElement(event, 'point')
        point.set('lat', str(self.lat))
        point.set('lon', str(self.lon))
        point.set('hae', str(self.alt))
        point.set('ce', '35.0')
        point.set('le', '999999')

        detail = etree.SubElement(event, 'detail')

        contact = etree.SubElement(detail, 'contact')
        contact.set('endpoint', '')
        contact.set('phone', '')
        contact.set('callsign', self.id)

        precisionlocation = etree.SubElement(detail, 'precisionlocation')
        precisionlocation.set('geopointsrc', 'gps')
        precisionlocation.set('altsrc', 'gps')

        remarks = etree.SubElement(detail, 'remarks')
        remarks.text = (f"Description: {self.description}, Speed: {self.speed} m/s, VSpeed: {self.vspeed} m/s, "
                        f"Altitude: {self.alt} m, Height: {self.height} m, Pilot Lat: {self.pilot_lat}, Pilot Lon: {self.pilot_lon}")

        color = etree.SubElement(detail, 'color')
        color.set('argb', '-256')

        usericon = etree.SubElement(detail, 'usericon')
        usericon.set('iconsetpath', '34ae1613-9645-4222-a9d2-e5f243dea2865/Military/UAV_quad.png')

        return etree.tostring(event, pretty_print=True, xml_declaration=True, encoding='UTF-8')


class TAKClient:
    """A client for connecting to a TAK server using TLS and sending CoT messages."""
    def __init__(self, tak_host: str, tak_port: int, tak_tls_context: Optional[ssl.SSLContext]):
        self.tak_host = tak_host
        self.tak_port = tak_port
        self.tak_tls_context = tak_tls_context
        self.sock = None

    def connect(self):
        """Establish a connection to the TAK server."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.tak_tls_context:
                self.sock = self.tak_tls_context.wrap_socket(self.sock)
            self.sock.connect((self.tak_host, self.tak_port))
            logger.debug("Connected to TAK server")
        except Exception as e:
            logger.error(f"Error connecting to TAK server: {e}")

    def send(self, cot_xml: bytes):
        """Send a CoT XML message to the TAK server."""
        try:
            if self.sock is None:
                self.connect()
            self.sock.send(cot_xml)
            logger.debug(f"Sent CoT to TAK server: {cot_xml}")
        except Exception as e:
            logger.error(f"Error sending to TAK server: {e}")
            self.sock = None  # Force reconnect on next send

    def close(self):
        """Close the connection to the TAK server."""
        if self.sock:
            self.sock.close()
            self.sock = None
            logger.debug("Closed connection to TAK server")


def send_to_tak_udp(cot_xml: bytes, tak_host: str, tak_port: int):
    """Send a CoT XML message to the TAK server via UDP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(cot_xml, (tak_host, tak_port))
        sock.close()
        logger.debug(f"Sent CoT to TAK server: {cot_xml}")
    except Exception as e:
        logger.error(f"Error sending to TAK server: {e}")


def send_to_tak_udp_multicast(cot_xml: bytes, multicast_address: str, multicast_port: int):
    """Send a CoT XML message to a multicast address via UDP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.sendto(cot_xml, (multicast_address, multicast_port))
        sock.close()
        logger.debug(f"Sent CoT to multicast address: {cot_xml}")
    except Exception as e:
        logger.error(f"Error sending to multicast address: {e}")


def parse_float(value: str) -> float:
    """Parse a string to a float, ignoring any extraneous characters."""
    try:
        return float(value.split()[0])
    except (ValueError, AttributeError):
        return 0.0


class DroneManager:
    def __init__(self, max_drones=30, rate_limit=1.0):
        self.drones = deque(maxlen=max_drones)
        self.drone_dict = {}
        self.rate_limit = rate_limit
        self.last_sent_time = time.time()

    def update_or_add_drone(self, drone_id, drone_data):
        if drone_id not in self.drone_dict:
            if len(self.drones) >= self.drones.maxlen:
                oldest_drone = self.drones.popleft()
                del self.drone_dict[oldest_drone.id]
            self.drones.append(drone_id)
            self.drone_dict[drone_id] = drone_data
        else:
            self.drone_dict[drone_id].update(
                lat=drone_data.lat,
                lon=drone_data.lon,
                speed=drone_data.speed,
                vspeed=drone_data.vspeed,
                alt=drone_data.alt,
                height=drone_data.height,
                pilot_lat=drone_data.pilot_lat,
                pilot_lon=drone_data.pilot_lon,
                description=drone_data.description
            )

    def send_updates(self, tak_client, tak_host, tak_port, enable_multicast, multicast_address, multicast_port):
        if time.time() - self.last_sent_time >= self.rate_limit:
            for drone_id in self.drones:
                cot_xml = self.drone_dict[drone_id].to_cot_xml()

                if tak_client:
                    tak_client.send(cot_xml)
                elif tak_host and tak_port:
                    send_to_tak_udp(cot_xml, tak_host, tak_port)
                
                if enable_multicast and multicast_address and multicast_port:
                    send_to_tak_udp_multicast(cot_xml, multicast_address, multicast_port)

            self.last_sent_time = time.time()


def zmq_to_cot(zmq_host, zmq_port, tak_host=None, tak_port=None, tak_tls_context=None, multicast_address=None, multicast_port=None, enable_multicast=False, rate_limit=1.0, max_drones=30):
    context = zmq.Context()
    zmq_socket = context.socket(zmq.SUB)
    zmq_socket.connect(f"tcp://{zmq_host}:{zmq_port}")
    zmq_socket.setsockopt_string(zmq.SUBSCRIBE, "")

    drone_manager = DroneManager(max_drones=max_drones, rate_limit=rate_limit)
    tak_client = TAKClient(tak_host, tak_port, tak_tls_context) if tak_host and tak_port and tak_tls_context else None

    def signal_handler(sig, frame):
        """Handle signal interruptions for graceful shutdown."""
        print("Interrupted by user")
        zmq_socket.close()
        context.term()
        if tak_client:
            tak_client.close()
        print("Cleaned up ZMQ resources")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    try:
        while True:
            try:
                message = zmq_socket.recv_json()
                logger.debug(f"Received JSON: {message}")

                drone_info = {}
                for item in message:
                    if 'Basic ID' in item:
                        id_type = item['Basic ID'].get('id_type')
                        if id_type == 'Serial Number (ANSI/CTA-2063-A)':
                            drone_info['id'] = item['Basic ID'].get('id', 'unknown')
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

                drone_manager.send_updates(tak_client, tak_host, tak_port, enable_multicast, multicast_address, multicast_port)

            except Exception as e:
                logger.error(f"Error receiving or processing message: {e}")
    except KeyboardInterrupt:
        signal_handler(None, None)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZMQ to CoT converter.")
    parser.add_argument("--zmq-host", default="127.0.0.1", help="ZMQ server host")
    parser.add_argument("--zmq-port", type=int, default=12345, help="ZMQ server port")
    parser.add_argument("--tak-host", type=str, help="TAK server hostname or IP address (optional)")
    parser.add_argument("--tak-port", type=int, help="TAK server port (optional)")
    parser.add_argument("--tak-tls-p12", type=str, help="Path to TAK server TLS PKCS#12 file (optional)")
    parser.add_argument("--tak-tls-p12-pass", type=str, help="Password for TAK server TLS PKCS#12 file (optional)")
    parser.add_argument("--tak-tls-skip-verify", action="store_true", help="(UNSAFE) Disable TLS server verification")
    parser.add_argument("--tak-multicast-addr", type=str, default="239.2.3.1", help="ATAK multicast address (optional)")
    parser.add_argument("--tak-multicast-port", type=int, default=6969, help="ATAK multicast port (optional)")
    parser.add_argument("--enable-multicast", action="store_true", help="Enable sending to multicast address")
    parser.add_argument("--rate-limit", type=float, default=1.0, help="Rate limit for sending CoT messages (seconds)")
    parser.add_argument("--max-drones", type=int, default=30, help="Maximum number of drones to track simultaneously")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)

    tak_tls_context = None
    if args.tak_tls_p12:
        try:
            with open(args.tak_tls_p12, 'rb') as p12_file:
                p12_data = p12_file.read()
        except OSError as err:
            logger.critical("Failed to read TAK server TLS PKCS#12 file: %s.", err)
            exit(1)

        p12_pass = None
        pem_encryption = cryptography.hazmat.primitives.serialization.NoEncryption()
        if args.tak_tls_p12_pass:
            p12_pass = args.tak_tls_p12_pass.encode()
            pem_encryption = cryptography.hazmat.primitives.serialization.BestAvailableEncryption(p12_pass)

        try:
            key, cert, more_certs = cryptography.hazmat.primitives.serialization.pkcs12.load_key_and_certificates(p12_data, p12_pass)
        except Exception as err:
            logger.critical("Failed to load TAK server TLS PKCS#12: %s.", err)
            exit(1)

        key_bytes = key.private_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM,
                                      cryptography.hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL,
                                      pem_encryption)
        cert_bytes = cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM)
        ca_bytes = b"".join(cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM) for cert in more_certs)

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
        if args.tak_tls_skip_verify:
            tak_tls_context.check_hostname = False
            tak_tls_context.verify_mode = ssl.VerifyMode.CERT_NONE

    zmq_to_cot(args.zmq_host, args.zmq_port, args.tak_host, args.tak_port, tak_tls_context, args.tak_multicast_addr, args.tak_multicast_port, args.enable_multicast, args.rate_limit, args.max_drones)
