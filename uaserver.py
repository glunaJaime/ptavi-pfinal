#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import socketserver
from proxy_registrar import Log_Writer, read_config_file, dtd_ua

usage_error = 'usage error: python3 uaserver.py config'


class ServerHandler(socketserver.DatagramRequestHandler):
    sesion_data = []

    def handle(self):
        data = self.rfile.read().decode('utf-8')
        line = ''
        ip = self.client_address[0]
        port = self.client_address[1]
        log.received_from(ip, str(port), data.replace('\r\n', ' '))
        print(data)
        if 'invite' in data.lower():
            self.get_mp32rtp(data)
            line = 'SIP/2.0 100 Trying\r\n\r\n'
            line += 'SIP/2.0 180 Ringing\r\n\r\n'
            line += 'SIP/2.0 200 OK\r\n'
            line += 'Content-Type: application/sdp\r\n\r\n'
            line += 'v=0\r\no=' + config['account_username'] + ' '
            line += config['uaserver_ip'] + '\r\ns=sesionextraordinaria\r\n'
            line += 't=0\r\nm=audio ' + config['rtpaudio_puerto'] + ' RTP\r\n'
        elif 'ack' in data.lower():
            if len(self.sesion_data) != 0:
                mp32rtp = './mp32rtp -i ' + self.sesion_data[0] + ' -p '
                mp32rtp += self.sesion_data[1] + ' < ' + config['audio_path']
                address = self.sesion_data[0] + ':' + self.sesion_data[1]
                cvlc = 'cvlc rtp://@ ' + address
                os.system(mp32rtp + ' & ' + cvlc)
                self.sesion_data = []
                line = ''
        elif 'bye' in data.lower():
            line = 'SIP/2.0 200 OK\r\n'
        else:
            line = 'SIP/2.0 405 Method not Allowed\r\n'

        if line:
            log.sent_to(ip, str(port), line.replace('\r\n', ' '))
            self.wfile.write(bytes(line, 'utf-8') + b'\r\n')

    def get_mp32rtp(self, data):
        ip = data.split('\r\n')[4].split()[-1]
        port = data.split('\r\n')[7].split()[1]
        self.sesion_data.append(ip)
        self.sesion_data.append(port)

if __name__ == "__main__":

    if len(sys.argv) != 2:
        sys.exit(usage_error)
    else:
        xml_file = sys.argv[1]

    config = read_config_file(dtd_ua, xml_file)
    log = Log_Writer(config['log_path'], '%Y%m%d%H%M%S')
    address = (config['uaserver_ip'], int(config['uaserver_puerto']))

    uaserver = socketserver.UDPServer(address, ServerHandler)
    log.starting()
    print('Server listening at ' + address[0] + ':' + str(address[1]))
    try:
        uaserver.serve_forever()
    except KeyboardInterrupt:
        log.finishing()
        print("Finalizado servidor")
