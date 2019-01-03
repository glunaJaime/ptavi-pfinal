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
        # leemos y decodificamos el mensaje recibido
        data = self.rfile.read().decode('utf-8')
        line = ''
        # sacamos la ip y el puerto de donde ha venido el mensaje
        ip = self.client_address[0]
        port = self.client_address[1]
        # escribimos el el log el mensaje recibido
        log.received_from(ip, str(port), data.replace('\r\n', ' '))
        # mostramos por pantalla el mensaje
        print(data)
        # si nos ha llegado un invite
        if 'invite' in data.lower():
            # obtenemos lo necesario para ejecutar mp32rtp
            self.get_mp32rtp(data)
            # creamos el mensaje de respuesta
            # 100 trying
            line = 'SIP/2.0 100 Trying\r\n\r\n'
            # 180 ringing
            line += 'SIP/2.0 180 Ringing\r\n\r\n'
            # 200 ok
            line += 'SIP/2.0 200 OK\r\n'
            # añadimos cabecera y parametros sdp
            line += 'Content-Type: application/sdp\r\n\r\n'
            line += 'v=0\r\no=' + config['account_username'] + ' '
            line += config['uaserver_ip'] + '\r\ns=sesionextraordinaria\r\n'
            line += 't=0\r\nm=audio ' + config['rtpaudio_puerto'] + ' RTP\r\n'
        # si nos ha llegado un ack
        elif 'ack' in data.lower():
            # para evitar ejecutar mp32rtp y cvlc sin que haber recibido antes
            # un invite comprobamos si los datos de la sesion obtenidos cuando
            # llego el invite estan, es decir, el len de la lista es mayor que
            # 0 y menor de 3
            if len(self.sesion_data) > 0 and len(self.sesion_data) < 3:
                # creamos el comando para ejecutar m32rtp
                mp32rtp = './mp32rtp -i ' + self.sesion_data[0] + ' -p '
                mp32rtp += self.sesion_data[1] + ' < ' + config['audio_path']
                address = self.sesion_data[0] + ':' + self.sesion_data[1]
                # creamos el comando para ejecutar cvlc
                cvlc = 'cvlc rtp://@ ' + address
                # ejecutamos ambos comandos
                os.system(mp32rtp + ' & ' + cvlc)
                # dejamos vacia la lista con los datos de la sesion
                self.sesion_data = []
                line = ''
        # si nos ha llegado un bye
        elif 'bye' in data.lower():
            line = 'SIP/2.0 200 OK\r\n'
        # si nos llega cualquier otro tipo de mensaje
        else:
            line = 'SIP/2.0 405 Method not Allowed\r\n'

        if line:
            log.sent_to(ip, str(port), line.replace('\r\n', ' '))
            self.wfile.write(bytes(line, 'utf-8') + b'\r\n')

    def get_mp32rtp(self, data):
        # buscamos la ip
        ip = data.split('\r\n')[4].split()[-1]
        # buscamos el puerto
        port = data.split('\r\n')[7].split()[1]
        self.sesion_data.append(ip)
        self.sesion_data.append(port)

if __name__ == "__main__":

    # comprobamos que no haya errores en los parametros introducidos
    if len(sys.argv) != 2:
        sys.exit(usage_error)
    else:
        xml_file = sys.argv[1]

    # creamos el fichero de configuracion
    config = read_config_file(dtd_ua, xml_file)
    # creamos el objeto de log
    log = Log_Writer(config['log_path'], '%Y%m%d%H%M%S')
    # creamos una tupla con la direccion en la que recibiremos los mensajes
    address = (config['uaserver_ip'], int(config['uaserver_puerto']))

    # creamos el servidor
    uaserver = socketserver.UDPServer(address, ServerHandler)
    # escribimos en el log
    log.starting()
    print('Server listening at ' + address[0] + ':' + str(address[1]))
    try:
        uaserver.serve_forever()
    except KeyboardInterrupt:
        # si se pulsa Ctrl+C
        log.finishing()
        print("Finalizado servidor")
