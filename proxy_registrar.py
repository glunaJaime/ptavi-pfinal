#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os,sys,time,json,socket,socketserver

from hashlib import md5
from xml.sax import make_parser
from xml.sax.handler import ContentHandler

dtd_ua = {'account': ['username', 'passwd'],
          'uaserver': ['ip', 'puerto'],
          'rtpaudio': ['puerto'],
          'regproxy': ['ip', 'puerto'],
          'log': ['path'],
          'audio':['path']}

dtd_pr = {'server': ['name','ip','puerto'],
          'database': ['path','passwdpath'],
          'log': ['path']}

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

def read_config_file(dtd,xml_file):

    parser = make_parser()
    xml_list = XMLHandler(dtd)
    parser.setContentHandler(xml_list)
    parser.parse(open(xml_file))

    return xml_list.get_tags()


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
            log.write(line + '\n')

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
    cdata = {}
    cpasswd = {}
    methods_allowed = ['register','invite','bye','ack']

    def register2json(self):

        with open(config['database_path'], 'w') as registered_file:
            json.dump(self.cdata,registered_file,sort_keys=True,indent=4)

    def json2registered(self):

        try:
            with open(config['database_path'], 'r') as registered_file:
                self.cdata = json.load(registered_file)
        except(FileNotFoundError):
            pass

        try:
            with open(config['database_passwdpath'], 'r') as passwd_file:
                    self.cpasswd = json.load(passwd_file)
        except(FileNotFoundError):
            pass

    def expired_users(self):

        time_str = self.expires_date(0)
        deleted = []
        for user in self.cdata:
            if self.cdata[user]['expires'] <= time_str:
                deleted.append(user)
        for user in deleted:
            self.cdata.pop(user)

    def handle(self):

        self.json2registered()
        data = self.rfile.read().decode('utf-8')
        address = [self.client_address[0],str(self.client_address[1])]
        log.received_from(address[0],address[1],data.replace('\r\n',' '))
        if 'SIP/2.0' in data:
            mess = data.split('\r\n')
            print_mess = mess[0].split()[0].lower() + ' received'
            if mess[0].split()[0].lower() in self.methods_allowed:
                if 'register' in mess[0].lower():
                    user = mess[0].split()[1].split(':')[1]
                    print_mess += ' from ' + user
                    port = mess[0].split()[1].split(':')[-1]
                    expires = mess[1].split()[1]
                    if user in self.cdata:
                        if int(expires) == 0:
                            print_mess += ': deleted'
                            del self.cdata[user]
                        else:
                            print_mess += ': change expires time'
                            self.cdata[user]['expires'] = self.expires_date(expires)
                        line = 'SIP/2.0 200 OK\r\n'
                    else:
                        if 'Digest response' in data:
                            nonce = digest_nonce(user)
                            response = digest_response(nonce,self.cpasswd[user])
                            response_user = mess[2].split('"')[-2]
                            if response == response_user:
                                print_mess += ': accepted'
                                line = 'SIP/2.0 200 OK\r\n'
                                address = self.client_address[0]+':'+port
                                expires_time = self.expires_date(expires)
                                self.cdata[user] = {'address':address,
                                                    'expires':expires_time}
                            else:
                                print_mess += ': denied'
                                line = ''
                        else:
                            print_mess += ': not authenticated'
                            nonce = digest_nonce(user)
                            line = 'SIP/2.0 401 Unathorized\r\n'
                            line +='WWW Authenticate: Digest nonce="' + nonce + '"\r\n'
                else:
                    user_dst = data.split('\r\n')[0].split()[1].split(':')[1]
                    print_mess += ' to ' + user_dst
                    if user_dst in self.cdata:
                        print_mess += ': resent'
                        line = self.resent(user_dst,data)
                    else:
                        print_mess += ': user not found'
                        line = 'SIP/2.0 404 User not Found\r\n'
            else:
                line = 'SIP/2.0 405 Method not Allowed\r\n'
        else:
            line = 'SIP/2.0 400 Bad Request\r\n'

        self.expired_users()
        self.register2json()
        print(print_mess)
        if line:
            log.sent_to(address[0],address[1],line.replace('\r\n',' '))
            self.wfile.write(bytes(line,'utf-8')+b'\r\n')

    def expires_date(self,exp):

        now = time.gmtime(time.time() + float(exp))

        return time.strftime('%Y-%m-%d %H:%M:%S',now)

    def resent(self,user_dst,line):

        ip = self.cdata[user_dst]['address'].split(':')[0]
        port = int(self.cdata[user_dst]['address'].split(':')[1])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
            my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            my_socket.connect((ip,port))
            log.sent_to(ip,str(port),line.replace('\r\n',' '))
            my_socket.send(bytes(line, 'utf-8'))
            try:
                data = my_socket.recv(1024).decode('utf-8')
                log.received_from(ip,str(port),data.replace('\r\n',' '))
            except:
                data = ''

        return data

if __name__ == "__main__":

    if len(sys.argv) != 2:
        sys.exit(usage_error)
    else:
        xml_file = sys.argv[1]

    config = read_config_file(dtd_pr,xml_file)
    log = Log_Writer(config['log_path'],'%Y%m%d%H%M%S')
    address = (config['server_ip'],int(config['server_puerto']))
    proxy = socketserver.UDPServer((ip,port),SIPRegisterHandler)

    log.starting()
    print(config['server_name'] + ' listening at ' + address[0] + ':' + address[1] + '\n')
    try:
        proxy.serve_forever()
    except KeyboardInterrupt:
        print("Finalizado servidor")
        log.finishing()
