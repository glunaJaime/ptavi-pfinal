#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import socket
import socketserver
from hashlib import md5
from xml.sax import make_parser
from xml.sax.handler import ContentHandler

dtd_ua = {'account': ['username', 'passwd'],
          'uaserver': ['ip', 'puerto'],
          'rtpaudio': ['puerto'],
          'regproxy': ['ip', 'puerto'],
          'log': ['path'],
          'audio': ['path']}

dtd_pr = {'server': ['name', 'ip', 'puerto'],
          'database': ['path', 'passwdpath'],
          'log': ['path']}


def digest_nonce(username, encoding='utf-8'):
    digest = md5()
    digest.update(bytes(username, encoding))
    digest.digest()

    return digest.hexdigest()


def digest_response(nonce, passwd, encoding='utf-8'):
    digest = md5()
    digest.update(bytes(nonce, encoding))
    digest.update(bytes(passwd, encoding))
    digest.digest()

    return digest.hexdigest()


class XMLHandler(ContentHandler):

    def __init__(self, att_list):

        self.list = {}
        self.config = att_list

    def startElement(self, name, attrs):

        if name in self.config:
            for att in self.config[name]:
                self.list[name + '_' + att] = attrs.get(att, '')

    def get_tags(self):

        return self.list


def read_config_file(dtd, xml_file):

    parser = make_parser()
    xml_list = XMLHandler(dtd)
    parser.setContentHandler(xml_list)
    parser.parse(open(xml_file))

    return xml_list.get_tags()


class Log_Writer:

    def __init__(self, log_file, date_format):

        if not os.path.exists(log_file):
            os.system('touch ' + log_file)
        self.file = log_file
        self.date_format = date_format

    def get_date(self):

        now = time.gmtime(time.time() + 3600)

        return time.strftime((self.date_format), now)

    def write(self, line):

        with open(self.file, 'a') as log:
            log.write(line + '\n')

    def starting(self):

        line = self.get_date() + ' Starting...'
        self.write(line)

    def sent_to(self, ip, port, mess):

        line = self.get_date() + ' Sent to '
        line += ip + ':' + port + ': '
        line += mess.replace('\r\n', ' ')
        self.write(line)

    def received_from(self, ip, port, mess):

        line = self.get_date() + ' Received from '
        line += ip + ':' + port + ': '
        line += mess.replace('\r\n', ' ')
        self.write(line)

    def error(self, type_error):

        line = self.get_date() + ' Error: ' + type_error
        self.write(line)

    def finishing(self):

        line = self.get_date() + ' Finishing.'
        self.write(line)


class SIPRegisterHandler(socketserver.DatagramRequestHandler):
    cdata = {}
    cpasswd = {}
    sesions = {}
    methods_allowed = ['register', 'invite', 'bye', 'ack']

    def register2json(self):

        # guardamos nuestro diccionario de clientes en un archivo .json
        with open(config['database_path'], 'w') as registered_file:
            json.dump(self.cdata, registered_file, sort_keys=True, indent=4)

    def json2registered(self):

        # obtenemos el diccionario de clientes activos
        try:
            # si el archivo existe, cogemos los datos
            with open(config['database_path'], 'r') as registered_file:
                self.cdata = json.load(registered_file)
        except(FileNotFoundError):
            # si no existe, dejamos el diccionario vacio
            pass

        # obtenemos el diccionario con las contraseñas de los clientes
        # seguimos el mismo procedimiento que para los clientes activos
        try:
            with open(config['database_passwdpath'], 'r') as passwd_file:
                    self.cpasswd = json.load(passwd_file)
        except(FileNotFoundError):
            pass

    def expired_users(self):

        # obtenemos la hora que es en este momento
        now = self.expires_date(0)
        deleted = []
        for user in self.cdata:
            # comprobamos si la fecha de expiracion del usuario ha pasado
            if self.cdata[user]['expires'] <= now:
                # si ya ha pasad su fecha de expiracion, lo guardamos en
                # una lista
                deleted.append(user)
        for user in deleted:
            # borramos los usuarios cuya fecha de expiracion haya pasado
            self.cdata.pop(user)

    def handle(self):

        # obtenemos el diccionario de clientes activos desde el fichero .json
        self.json2registered()
        # cogemos el mensaje recibido y lo decodificamos
        data = self.rfile.read().decode('utf-8')
        address = [self.client_address[0], str(self.client_address[1])]
        # escribimos en el fichero de log el mensaje que hemos recibido
        log.received_from(address[0], address[1], data.replace('\r\n', ' '))
        # comprobamos que el mensaje este bien formado
        if 'SIP/2.0' in data:
            mess = data.split('\r\n')
            print_mess = mess[0].split()[0].lower() + ' received'
            # comprobamos si el metodo esta entre los metodos permitidos
            if mess[0].split()[0].lower() in self.methods_allowed:
                # si tenemos un mensaje de tipo register
                if 'register' in mess[0].lower():
                    # obtenemos el usuario
                    user = mess[0].split()[1].split(':')[1]
                    print_mess += ' from ' + user
                    # obtenemos el puerto
                    port = mess[0].split()[1].split(':')[-1]
                    # y obtenemos el tiempo de expiracion
                    expires = mess[1].split()[1]
                    # comprobamos si el usuario esta en el diccionario de
                    # clientes activos
                    if user in self.cdata:
                        if int(expires) == 0:
                            print_mess += ': deleted'
                            del self.cdata[user]
                        else:
                            print_mess += ': change expires time'
                            exp_time = self.expires_date(expires)
                            self.cdata[user]['expires'] = exp_time
                        line = 'SIP/2.0 200 OK\r\n'
                    else:
                        # si no esta en el diccionario, comprobamos si es un
                        # register de autentificacion o no
                        if 'Digest response' in data:
                            # si es un register de autentificacion obtenemos el
                            # digest nonce
                            nonce = digest_nonce(user)
                            # obtenemos la contraseña del ussuario
                            passwd = self.cpasswd[user]
                            # creamos el digest response que deberia enviarnos el
                            # usuario
                            response = digest_response(nonce, passwd)
                            # obtenemos el digest response que nos ha enviado
                            response_user = mess[2].split('"')[-2]
                            # comparamos ambos digest response
                            if response == response_user:
                                # si son iguales, se acepta al usuario
                                print_mess += ': accepted'
                                # se envia un 200 OK
                                line = 'SIP/2.0 200 OK\r\n'
                                address = self.client_address[0] + ':' + port
                                expires_time = self.expires_date(expires)
                                # guardamos al usuario en nuestro diccionario
                                self.cdata[user] = {'address': address,
                                                    'expires': expires_time}
                            else:
                                # si son diferentes se le deniega
                                print_mess += ': denied'
                                # no le enviamos ninguna respuesta
                                line = ''
                        else:
                            # si no es un register de autentificacion, se le
                            # envia un 401 Unauthorized
                            print_mess += ': not authenticated'
                            # obtenemos el digest nonce del usario
                            nonce = digest_nonce(user)
                            # preparamos el mensaje
                            line = 'SIP/2.0 401 Unathorized\r\n'
                            line += 'WWW Authenticate: Digest nonce="'
                            line += nonce + '"\r\n'
                else:
                    # si no es un mensaje register, sera un invite, un bye o un ack
                    # en estos tres tipos de mensaje la primera linea se compone
                    # de la misma manera
                    user_dst = data.split('\r\n')[0].split()[1].split(':')[1]
                    print_mess += ' to ' + user_dst
                    # comprobamos que el usuario al que va dirigido el mensaje este
                    # en nuesro diccionario de clientes activos
                    if user_dst in self.cdata:
                        # comprobamos si es un invite o un bye, si es un ack no
                        # tendremos que hacer nada antes de reenviarlo
                        if 'invite' in data.lower() and self.correct_sdp(data):
                            # si es un mensaje de tipo invite y el cuerpo sdp esta bien
                            # formado, crea la sesion
                            sesion_name = self.get_sesion_name(data)
                            users = self.users_in_sesion(data)
                            self.sesions[sesion_name] = users
                        elif 'bye' in data.lower():
                            # comprueba si el usuario esta en alguna de las sesiones
                            # antes de eliminar la sesion
                            self.delete_sesion(user_dst)
                        print_mess += ': resent'
                        # reenvia el mensaje al usuario al que esta dirigido
                        line = self.resent(user_dst, data)
                    else:
                        print_mess += ': user not found'
                        line = 'SIP/2.0 404 User not Found\r\n'
            else:
                # si el metodo no esta entre los permitidos enviamos un
                # 405 Method Not Allowed
                line = 'SIP/2.0 405 Method Not Allowed\r\n'
        else:
            # si el mensaje esta mal formado enviamos un 400 Bad Request
            line = 'SIP/2.0 400 Bad Request\r\n'

        # comprobamos si alguno de los usuarios ha caducado
        self.expired_users()
        # guardamos los usuarios en un fichero .json
        self.register2json()
        print(print_mess)
        # si tenemos algo que enviar, lo enviamos
        if line:
            log.sent_to(address[0], address[1], line.replace('\r\n', ' '))
            self.wfile.write(bytes(line, 'utf-8') + b'\r\n')

    def get_sesion_name(self, data):

        # buscamos el nombre de la sesion dentro del mensaje
        for line in data.split('\r\n'):
            # la sesion siempre esta precedida de un s=
            if 's=' in line:
                sesion_name = line.split('=')[-1]
                break

        return sesion_name

    def users_in_sesion(self, data):

        # buscamos los usuarios en el mensaje
        for line in data.split('\r\n'):
            # el primer usuario estara en la primera linea, despues del sip:
            if 'sip' in line:
                user1 = line.split()[1].split(':')[-1]
            # el segundo estara precedido de o=, en el cuerpo sdp
            elif 'o=' in line:
                user2 = line.split('=')[-1].split()[0]

        return [user1, user2]

    def delete_sesion(self, user):

        # seguimos el mismo procedimiento que seguimos para eliminar los clientes
        # caducados
        deleted = []
        for sesion in self.sesions:
            if user in sesion:
                deleted.append(sesion)

        for sesion in deleted:
            del self.sesions[sesion]

    def correct_sdp(self, data):

        # comprobamos si el cuerpo de sdp esta bien formado
        # creamos un contador que inicializamos a 0
        i = 0
        # los parametros que tiene que contener los guardamos en una lista
        # los '' son espacios en blanco
        l = ['SIP/2.0', 'Content-Type', '', 'v', 'o', 's', 't', 'm', '', '']
        # dividimos el mensaje en lineas
        lines = data.split('\r\n')
        for j in range(0, len(lines)):
            # si el parametro de nuestra lista esta contenido en la linea del
            # mensaje, aumentamos en 1 nuestro contador
            if l[j] in lines[j]:
                i += 1

        # si el contador tiene la misma longitud que nustra lista, todos los
        # elementos estarán en el mensaje
        return i == len(l)

    def expires_date(self, exp):

        # obtenemos la fecha del momento en que expirara, sumando a la fecha de
        # este momento el tiempo de expiracion
        now = time.gmtime(time.time() + float(exp))

        # escribimos la fecha de expiracion con el formato que se desee
        return time.strftime('%Y-%m-%d %H:%M:%S', now)

    def resent(self, user_dst, line):

        # creamos un socket para reenviar el mensaje
        # sacamos la ip y el puerto del usuario al que se reenviara el mensaje
        ip = self.cdata[user_dst]['address'].split(':')[0]
        port = int(self.cdata[user_dst]['address'].split(':')[1])
        # creamos el socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
            my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            my_socket.connect((ip, port))
            log.sent_to(ip, str(port), line.replace('\r\n', ' '))
            # enviamos el mensaje al usario
            my_socket.send(bytes(line, 'utf-8'))
            # esperamos a que nos responda
            try:
                # si nos responde, decodificamos el mensaje
                data = my_socket.recv(1024).decode('utf-8')
                log.received_from(ip, str(port), data.replace('\r\n', ' '))
            except:
                # si no nos responde, no devolvemos nada
                data = ''

        return data

if __name__ == "__main__":

    # primero comprobamos que los paametros introducidos sean correctos
    if len(sys.argv) != 2:
        sys.exit(usage_error)
    else:
        xml_file = sys.argv[1]

    # despues obtenemos nuestro diccionario de configuracion a partir
    # del fichero introducido como parametro
    config = read_config_file(dtd_pr, xml_file)
    log = Log_Writer(config['log_path'], '%Y%m%d%H%M%S')
    address = (config['server_ip'], int(config['server_puerto']))
    proxy = socketserver.UDPServer(address, SIPRegisterHandler)

    # creamos el servidor
    log.starting()
    server_mess = config['server_name'] + ' listening at '
    server_mess += address[0] + ':' + str(address[1])
    print(server_mess + '\n')
    try:
        proxy.serve_forever()
    except KeyboardInterrupt:
        # al pulsar Ctrl+C terminaremos la ejecucion
        print("Finalizado servidor")
        log.finishing()
