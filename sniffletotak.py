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

import zmq
import socket
import json
import argparse
import signal
import sys
import datetime
from lxml import etree
import logging
from typing import Optional

# Setup logging
logger = logging.getLogger(__name__)

class Drone:
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

    def to_cot_xml(self) -> bytes:
        event = etree.Element('event')
        event.set('version', '2.0')
        event.set('uid', f"drone-{self.id}")
        event.set('type', 'b-m-p-s-m')
        event.set('time', datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.995Z'))
        event.set('start', datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.995Z'))
        event.set('stale', (datetime.datetime.utcnow() + datetime.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S.995Z'))
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
        remarks.text = f"Description: {self.description}, Speed: {self.speed} m/s, VSpeed: {self.vspeed} m/s, Altitude: {self.alt} m, Height: {self.height} m, Pilot Lat: {self.pilot_lat}, Pilot Lon: {self.pilot_lon}"

        color = etree.SubElement(detail, 'color')
        color.set('argb', '-256')

        usericon = etree.SubElement(detail, 'usericon')
        usericon.set('iconsetpath', '34ae1613-9645-4222-a9d2-e5f243dea2865/Military/UAV_quad.png')

        return etree.tostring(event, pretty_print=True, xml_declaration=True, encoding='UTF-8')

def send_to_tak(cot_xml: bytes, tak_host: str, tak_port: int):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(cot_xml, (tak_host, tak_port))
        sock.close()
        logger.debug(f"Sent CoT to TAK server: {cot_xml}")
    except Exception as e:
        logger.error(f"Error sending to TAK server: {e}")

def send_to_multicast(cot_xml: bytes, multicast_address: str, multicast_port: int):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.sendto(cot_xml, (multicast_address, multicast_port))
        sock.close()
        logger.debug(f"Sent CoT to multicast address: {cot_xml}")
    except Exception as e:
        logger.error(f"Error sending to multicast address: {e}")

def parse_float(value: str) -> float:
    try:
        # Remove any units or extraneous characters
        return float(value.split()[0])
    except (ValueError, AttributeError):
        return 0.0

def zmq_to_cot(zmq_host, zmq_port, tak_host=None, tak_port=None, multicast_address=None, multicast_port=None):
    context = zmq.Context()
    zmq_socket = context.socket(zmq.SUB)
    zmq_socket.connect(f"tcp://{zmq_host}:{zmq_port}")
    zmq_socket.setsockopt_string(zmq.SUBSCRIBE, "")

    def signal_handler(sig, frame):
        print("Interrupted by user")
        zmq_socket.close()
        context.term()
        print("Cleaned up ZMQ resources")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    try:
        while True:
            try:
                message = zmq_socket.recv_json()
                logger.debug(f"Received JSON: {message}")

                for item in message:
                    try:
                        # Extract relevant fields from each item in the list
                        id = item.get("Basic ID", {}).get("id", "unknown")
                        description = item.get("Self-ID Message", {}).get("text", "")
                        lat = parse_float(item.get("Location/Vector Message", {}).get("latitude", "0.0"))
                        lon = parse_float(item.get("Location/Vector Message", {}).get("longitude", "0.0"))
                        speed = parse_float(item.get("Location/Vector Message", {}).get("speed", "0.0").split()[0])
                        vspeed = parse_float(item.get("Location/Vector Message", {}).get("vert_speed", "0.0").split()[0])
                        alt = parse_float(item.get("Location/Vector Message", {}).get("geodetic_altitude", "0.0").split()[0])
                        height = parse_float(item.get("Location/Vector Message", {}).get("height_agl", "0.0").split()[0])
                        pilot_lat = parse_float(item.get("System Message", {}).get("latitude", "0.0"))
                        pilot_lon = parse_float(item.get("System Message", {}).get("longitude", "0.0"))

                        # Convert the message to a CoT format
                        drone = Drone(
                            id=id,
                            lat=lat,
                            lon=lon,
                            speed=speed,
                            vspeed=vspeed,
                            alt=alt,
                            height=height,
                            pilot_lat=pilot_lat,
                            pilot_lon=pilot_lon,
                            description=description
                        )
                        cot_xml = drone.to_cot_xml()

                        # Send the CoT message to TAK server if provided
                        if tak_host and tak_port:
                            send_to_tak(cot_xml, tak_host, tak_port)

                        # Optionally send to ATAK multicast port if provided
                        if multicast_address and multicast_port:
                            send_to_multicast(cot_xml, multicast_address, multicast_port)
                    except Exception as e:
                        logger.error(f"Error processing item: {item}, Error: {e}")
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
    parser.add_argument("--multicast-address", type=str, default="239.2.3.1", help="ATAK multicast address (optional)")
    parser.add_argument("--multicast-port", type=int, default=6969, help="ATAK multicast port (optional)")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)

    zmq_to_cot(args.zmq_host, args.zmq_port, args.tak_host, args.tak_port, args.multicast_address, args.multicast_port)
