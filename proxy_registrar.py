#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import time
from xml.sax import make_parser
from xml.sax.handler import ContentHandler

date_log = '%Y%m%d%H%M%S'

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
