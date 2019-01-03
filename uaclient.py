#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import socket
from proxy_registrar import Log_Writer, digest_response
from proxy_registrar import read_config_file, dtd_ua

usage_error = 'usage: python3 uaclient.py config method option'


class SIPMessages:

    # se crea una clase para crear los mensajes que puede enviar
    # el cliente
    def __init__(self, username, address, rtpport):

        self.user = username
        self.address = address
        self.rtpport = rtpport

    def get_message(self, method, option, digest=''):

        # dependiendo del metodo elegido se usa una opcion u otra
        if method.lower() == 'register':
            mess = self.register(option, digest)
        elif method.lower() == 'invite':
            mess = self.invite(option)
        elif method.lower() == 'bye':
            mess = self.bye(option)
        elif method.lower() == 'ack':
            mess = self.ack(option)
        else:
            # para poder recibir un 405 dejamos esta opcion
            mess = method.upper() + ' ' + self.user + ' SIP/2.0'

        return mess + '\r\n'

    def register(self, option, digest=''):

        # metodo register
        mess = 'REGISTER sip:' + self.user + ':' + self.address[1]
        mess += ' SIP/2.0\r\nExpires: ' + option
        if digest != '':
            # si nos ha llegado un 401 introducimos el digest
            mess += '\r\nAuthorization: Digest response="' + digest + '"'

        return mess

    def invite(self, option):

        # metodo invite
        mess = 'INVITE sip:' + option + ' SIP/2.0\r\n'
        mess += 'Content-Type: application/sdp\r\n\r\n'
        mess += 'v=0\r\no=' + self.user + ' ' + self.address[0]
        mess += '\r\ns=sesionextraordinaria\r\nt=0\r\n'
        mess += 'm=audio ' + self.rtpport + ' RTP'

        return mess

    def bye(self, option):

        # metodo bye
        mess = 'BYE sip:' + option + ' SIP/2.0'

        return mess

    def ack(self, option):

        # ack
        mess = 'ACK sip:' + option + ' SIP/2.0'

        return mess


# para enviar un mensaje creamos una funcion, se le introducen
# como parametros un socket, la direccion a la que vamos a enviar
# y el mensaje que queremos enviar
def send(socket, address, mess):

    socket.connect(address)
    print("Sent:\n" + mess)
    socket.send(bytes(mess, 'utf-8') + b'\r\n')
    log.sent_to(address[0], str(address[1]), mess.replace('\r\n', ' '))

# para recibit creamos una funcion tambien, le introduciremos como
# parametro unicamente un socket
def receive(socket):

    try:
        return socket.recv(1024).decode('utf-8')
    except:
        address = pr_address[0] + ':' + str(pr_address[1])
        log.error('No server listenning at ' + address)
        sys.exit('Connection refused')

# comprobamos los parametros introducidos por si hay algun error
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

# creamos el diccionario de configuracion
config = read_config_file(dtd_ua, xml_file)
# creamos el objeto para escribir en el fichero de log
log = Log_Writer(config['log_path'], '%Y%m%d%H%M%S')
# sacamos los parametros que vamos a utilizar
user = config['account_username']
rtpport = config['rtpaudio_puerto']
server_address = [config['uaserver_ip'], config['uaserver_puerto']]
# creamos el objeto para obtener los mensajes del cliente
sip_mess = SIPMessages(user, server_address, rtpport)

# escribimos en el log que empezamos
log.starting()
# creamos la direccion del proxy
pr_address = (config['regproxy_ip'], int(config['regproxy_puerto']))
# creamos el mensaje que vamos a enviar
line = sip_mess.get_message(method, str(option))
# creamos el socket que vamos a utilizar
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # enviamos el mensaje
    send(my_socket, pr_address, line)
    # esperamos la respuesta del proxy
    data = receive(my_socket)
    log_data = data.replace('\r\n', ' ')
    # escribimos la respuesta del proxy en el log
    log.received_from(pr_address[0], str(pr_address[1]), log_data)
    # si nos envia un 401 Unathorized
    if '401' in data:
        # obtenemos la contraseña del fichero de configuracion
        passwd = config['account_passwd']
        # sacamos el digest nonce del mensaje recibido
        nonce = data.split('"')[1]
        # con el nonce y la contraseña, obtenemos el response
        response = digest_response(nonce, passwd)
        # creamos el mensaje de nuevo, esta vez con el digest
        line = sip_mess.get_message(method, str(option), response)
        # volvemos a enviar el mensaje y esperamos respuesta
        send(my_socket, pr_address, line)
        data = receive(my_socket)
        # escribimos en el fichero de log lo que hemos recibido
        log_data = data.replace('\r\n', ' ')
        log.received_from(pr_address[0], str(pr_address[1]), log_data)
        # mostramos por pantalla el mensaje recibido
        print(data.replace('\r\n', ' '))
    # buscamos la respuesta al invite, es decir, 100 Trying, 180 Ringing
    # y 200 ok
    elif '200' in data:
        # el 200 ok puede llegar tambien solo, cuando se envia un bye
        if '180' in data:
            if '100' in data:
                # creamos el mensaje ack y lo enviamos
                line = sip_mess.get_message('ack', str(option))
                send(my_socket, pr_address, line)
                log_line = line.replace('\r\n', ' ')
                log.sent_to(pr_address[0], str(pr_address[1]), log_line)
        else:
            # escribimos por pantalla el mensaje recibido
            print(data.replace('\r\n', ' '))
    else:
        # escribimos por pantalla el mensaje recibido
        print(data.replace('\r\n', ' '))

# escribimos en el log que hemos terminado
log.finishing()
my_socket.close()
