#!/usr/bin/python3
# -*- coding: utf-8 -*-
import os
import sys
import time
import json
import socketserver
from hashlib import md5
from xml.sax import make_parser
from xml.sax.handler import ContentHandler

def digest_nonce(username,encoding='utf-8'):
    digest = md5()
    digest.update(bytes(username,encoding))
    digest.digest()

    return digest.hexdigest()

def digest_response(nonce,passwd,encoding='utf-8'):
    digest = md5()
    digest.update(bytes(nonce,encoding))
    digest.update(bytes(passwd,encoding))
    digest.digest()

    return digest.hexdigest()
class XMLHandler(ContentHandler):

    def __init__(self,att_list):

        self.list = {}
        self.config = att_list

    def startElement(self, name, attrs):

        if name in self.config:
            for att in self.config[name]:
                self.list[name + '_' + att] = attrs.get(att, '')

    def get_tags(self):

        return self.list

class Log_Writer:

    def __init__(self,log_file,date_format):

        if not os.path.exists(log_file):
            os.system('touch ' + log_file)
        self.file = log_file
        self.date_format = date_format

    def get_date(self):

        return time.strftime((self.date_format),time.gmtime(time.time() + 3600))

    def write(self,line):

        with open(self.file,'a') as log:
            log.write(line+'\n')

    def starting(self):

        line = self.get_date() + ' Starting...'
        self.write(line)

    def sent_to(self,ip,port,mess):

        line = self.get_date() + ' Sent to '
        line += ip + ':' + port + ': ' 
        line += mess.replace('\r\n',' ')
        self.write(line)

    def received_from(self,ip,port,mess):

        line = self.get_date() + ' Received from '
        line += ip + ':' + port + ': ' 
        line += mess.replace('\r\n',' ')
        self.write(line)

    def error(self,type_error):

        line = self.get_date() + ' Error: ' + type_error
        self.write(line)

    def finishing(self):

        line = self.get_date() + ' Finishing.'
        self.write(line)

class SIPRegisterHandler(socketserver.DatagramRequestHandler):
    client_data = {}
    client_passwd = {}

    def register2json(self):

        with open(config['database_path'], 'w') as registered_file:
            json.dump(self.client_data,registered_file,sort_keys=True,indent=4)

    def json2registered(self):

        try:
            with open(config['database_path'], 'r') as registered_file:
                self.client_data = json.load(registered_file)
            with open(config['database_passwdpath'], 'r') as passwd_file:
                self.client_passwd = json.load(passwd_file)
        except(FileNotFoundError):
            pass

    def expired_users(self):

        pass

    def handle(self):

        self.json2registered()
        data = self.rfile.read().decode('utf-8')
        address = [self.client_address[0],str(self.client_address[1])]
        log.received_from(address[0],address[1],data.replace('\r\n',' '))
        print(data)
        if 'SIP/2.0' in data:
            mess = data.split('\r\n')
            if 'register' in mess[0].lower():
                user = mess[0].split()[1].split(':')[1]
                port = mess[0].split()[1].split(':')[-1]
                expires = mess[1].split()[1]
                if user in self.client_data:
                    # 200 ok
                    line = 'SIP/2.0 200 OK\r\n'
                else:
                    # 401 unathorized
                    if 'Digest response' in data:
                        response = ''
                        response_user = ''
                        if response == response_user:
                            # 200 ok y guardar
                            line = 'SIP/2.0 200 OK\r\n'
                            time_expire = time.strftime('%Y-%m-%d %H:%M:%S',
                                          time.gmtime(time.time() + float(expires)))
                            self.client_data[user] = {'address':self.client_address[0]+':'+port,
                                                      'expires':time_expire}
                        else:
                            pass
                    else:
                        line = 'SIP/2.0 401 Unathorized\r\nWWW Authenticate: Digest nonce="'
                        line += digest_nonce(user) + '"\r\n'
            elif 'invite' in mess[0].lower():
                # buscar usuario destino y enviar
                pass
            elif 'bye' in mess[0].lower():
                # buscar usuario destino y enviar
                pass
            elif 'ack' in mess[0].lower():
                # buscar usuario destino y enviar
                pass
            else:
                # 405 method not allowed
                line = 'SIP/2.0 405 Method not Allowed\r\n'
        else:
            # enviar 400 Bad Request
            line = 'SIP/2.0 400 Bad Request\r\n'

        self.expired_users()
        log.sent_to(address[0],address[1],line.replace('\r\n',' '))
        self.wfile.write(bytes(line,'utf-8')+b'\r\n')
        self.register2json()
        
if __name__ == "__main__":

    if len(sys.argv) != 2:
        sys.exit(usage_error)
    else:
        xml_file = sys.argv[1]

    config = {'server': ['name','ip','puerto'],
              'database': ['path','passwdpath'],
              'log': ['path']}

    parser = make_parser()
    xml_list = XMLHandler(config)
    parser.setContentHandler(xml_list)
    parser.parse(open(xml_file))

    config = xml_list.get_tags()
    log = Log_Writer(config['log_path'],'%Y%m%d%H%M%S')

    ip = config['server_ip']
    port = int(config['server_puerto'])

    serv = socketserver.UDPServer((ip,port),SIPRegisterHandler)

    log.starting()
    print(config['server_name'] + ' listening at ' + config['server_puerto'])
    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        print("Finalizado servidor")
