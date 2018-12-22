#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
import socket
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from proxy_registrar import XMLHandler,Log_Writer,digest_response

usage_error = 'usage: python3 uaclient.py config method option'
methods_allowed = ['register','invite','bye']

class SIPMessages:

    def __init__(self,username,ip,port,rtpport):

        self.user = username
        self.address = [ip, port]
        self.rtpport = rtpport

    def get_message(self,method,option,digest=''):

        if method.lower() == 'register':
            mess = self.register(option,digest)
        elif method.lower() == 'invite':
            mess = self.invite(option)
        elif method.lower() == 'bye':
            mess = self.bye(option)
        elif method.lower() == 'ack':
            mess = self.ack(option)
        else:
            mess = method.upper() + ' ' + self.user + ' SIP/2.0'

        return mess + '\r\n'

    def register(self,option,digest=''):

        mess = 'REGISTER sip:' + self.user + ':' + self.address[1]
        mess += ' SIP/2.0\r\nExpires: ' + option
        if digest != '':
            mess += '\r\nAuthorization: Digest response="' + digest + '"'

        return mess

    def invite(self,option):

        mess = 'INVITE sip:' + option + ' SIP/2.0\r\n'
        mess += 'Content-Type: application/sdp\r\n\r\n'
        mess += 'v=0\r\no=' + self.user + ' ' + self.address[0]
        mess += '\r\ns=sesionextraordinaria\r\nt=0\r\n'
        mess += 'm=audio ' + self.rtpport + ' RTP'

        return mess

    def bye(self,option):

        mess = 'BYE sip:' + option + ' SIP/2.0'

        return mess

    def ack(self,option):

        mess = 'ACK sip:' + option + ' SIP/2.0'

        return mess

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

config = {'account': ['username', 'passwd'],
          'uaserver': ['ip', 'puerto'],
          'rtpaudio': ['puerto'],
          'regproxy': ['ip', 'puerto'],
          'log': ['path'],
          'audio':['path']}

parser = make_parser()
xml_list = XMLHandler(config)
parser.setContentHandler(xml_list)
parser.parse(open(xml_file))

config = xml_list.get_tags()
log = Log_Writer(config['log_path'],'%Y%m%d%H%M%S')
user = config['account_username']
address = (config['uaserver_ip'],config['uaserver_puerto'])
rtpport = config['rtpaudio_puerto']
sip_mess = SIPMessages(user,address[0],address[1],rtpport)

log.starting()
pr_ip = config['regproxy_ip']
pr_port = config['regproxy_puerto']

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.connect((pr_ip,int(pr_port)))
    line = sip_mess.get_message(method,str(option))
    print("Sent: " + line)
    my_socket.send(bytes(line, 'utf-8') + b'\r\n')
    log.sent_to(pr_ip,pr_port,line.replace('\r\n',' '))
    try:
        data = my_socket.recv(1024).decode('utf-8')
    except:
        log.error('No server listening at ' + pr_ip + ' port ' + pr_port)
        sys.exit('Connection refused')
    log.received_from(pr_ip,pr_port,data.replace('\r\n',' '))
    if '401' in data:
        passwd = config['account_passwd']
        nonce = data.split('"')[1]
        line = sip_mess.get_message(method,str(option),digest_response(nonce,passwd))
        my_socket.send(bytes(line, 'utf-8') + b'\r\n')
        log.sent_to(pr_ip,pr_port,line.replace('\r\n',' '))
    elif '200' in data:
        # todo correcto
        print(data.replace('\r\n',' '))
    elif ['100','180','200'] in data:
        # enviar ack
        line = sip_mess.get_message('ack',str(option))
        my_socket.send(bytes(line, 'utf-8') + b'\r\n')
    else:
        print(data.replace('\r\n',' '))

log.finishing()
my_socket.close()
