#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import socket
from proxy_registrar import Log_Writer, digest_response
from proxy_registrar import read_config_file, dtd_ua

usage_error = 'usage: python3 uaclient.py config method option'


class SIPMessages:

    def __init__(self, username, address, rtpport):

        self.user = username
        self.address = address
        self.rtpport = rtpport

    def get_message(self, method, option, digest=''):

        if method.lower() == 'register':
            mess = self.register(option, digest)
        elif method.lower() == 'invite':
            mess = self.invite(option)
        elif method.lower() == 'bye':
            mess = self.bye(option)
        elif method.lower() == 'ack':
            mess = self.ack(option)
        else:
            mess = method.upper() + ' ' + self.user + ' SIP/2.0'

        return mess + '\r\n'

    def register(self, option, digest=''):

        mess = 'REGISTER sip:' + self.user + ':' + self.address[1]
        mess += ' SIP/2.0\r\nExpires: ' + option
        if digest != '':
            mess += '\r\nAuthorization: Digest response="' + digest + '"'

        return mess

    def invite(self, option):

        mess = 'INVITE sip:' + option + ' SIP/2.0\r\n'
        mess += 'Content-Type: application/sdp\r\n\r\n'
        mess += 'v=0\r\no=' + self.user + ' ' + self.address[0]
        mess += '\r\ns=sesionextraordinaria\r\nt=0\r\n'
        mess += 'm=audio ' + self.rtpport + ' RTP'

        return mess

    def bye(self, option):

        mess = 'BYE sip:' + option + ' SIP/2.0'

        return mess

    def ack(self, option):

        mess = 'ACK sip:' + option + ' SIP/2.0'

        return mess


def send(socket, address, mess):

    socket.connect(address)
    print("Sent:\n" + mess)
    socket.send(bytes(mess, 'utf-8') + b'\r\n')
    log.sent_to(address[0], str(address[1]), mess.replace('\r\n', ' '))


def receive(socket):

    try:
        return socket.recv(1024).decode('utf-8')
    except:
        address = pr_address[0] + ':' + str(pr_address[1])
        log.error('No server listenning at ' + address)
        sys.exit('Connection refused')

if len(sys.argv) != 4:
    sys.exit(usage_error)
else:
    xml_file = sys.argv[1]
    method = sys.argv[2]
    if method.lower() == 'register':
        try:
            option = int(sys.argv[3])
        except:
            sys.exit(usage_error)
    else:
        option = sys.argv[3]

config = read_config_file(dtd_ua, xml_file)
log = Log_Writer(config['log_path'], '%Y%m%d%H%M%S')
user = config['account_username']
rtpport = config['rtpaudio_puerto']
server_address = [config['uaserver_ip'], config['uaserver_puerto']]
sip_mess = SIPMessages(user, server_address, rtpport)

log.starting()
pr_address = (config['regproxy_ip'], int(config['regproxy_puerto']))
line = sip_mess.get_message(method, str(option))
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    send(my_socket, pr_address, line)
    data = receive(my_socket)
    log_data = data.replace('\r\n', ' ')
    log.received_from(pr_address[0], str(pr_address[1]), log_data)
    if '401' in data:
        passwd = config['account_passwd']
        response = digest_response(data.split('"')[1], passwd)
        line = sip_mess.get_message(method, str(option), response)
        send(my_socket, pr_address, line)
        data = receive(my_socket)
        log_data = data.replace('\r\n', ' ')
        log.received_from(pr_address[0], str(pr_address[1]), log_data)
        print(data.replace('\r\n', ' '))
    elif '200' in data:
        if '180' in data:
            if '100' in data:
                line = sip_mess.get_message('ack', str(option))
                send(my_socket, pr_address, line)
                log_line = line.replace('\r\n', ' ')
                log.sent_to(pr_address[0], str(pr_address[1]), log_line)
        else:
            print(data.replace('\r\n', ' '))
    else:
        print(data.replace('\r\n', ' '))

log.finishing()
my_socket.close()
