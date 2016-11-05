# client side code

# authors: andre silva Santos
# pedro coelho


import sys
import socket
import select
import json
import os
import time
import util
import logging
import textwrap
from pprint import pprint
from random import randint
from datetime import datetime
from ui import ChatUI
from curses import wrapper

# Server address
HOST = ""  # All available interfaces
PORT = 8080  # The server port
BUFSIZE = 512 * 1024
MAX_BUFSIZE = 64 * 1024
TERMINATOR = "\n\n"
NAME = ""
ID = 0
PHASE = 0

STATE_NONE = 0
STATE_CONNECTED = 1
STATE_DISCONNECTED = 2


class Peer:
    def __init__(self, id, name, sa_data):
        self.id = id
        self.name = name
        self.sa_data = sa_data


class Client:
    def __init__(self):
        self.id = util.generate_nonce()
        self.phase = 1
        self.name = 'Unknown'
        self.ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ss.settimeout(4)
        # manage peers
        self.peers = {}  # id is key

        try:
            self.ss.connect((HOST, PORT))
        except:
            print 'Unable to Connect'
            sys.exit(-1)

        print 'Connected'

    def addPeer(self, pid, pname, psa_data):
        if pid in self.peers:
            print 'Already paired'
            return

        peer = Peer(pid, pname, psa_data)
        self.peers[peer.id] = peer
        print 'Paired with ' + peer.id

    def delPeer(self, pid):
        if pid not in self.peers:
            print 'Peer not found to delete'
            return

        peer = self.peers[pid]
        assert peer.id == pid, 'peer id does not match pid'
        del self.peers[peer.id]
        print 'Peer deleted'

    #TODO add capability to negotiate ciphers
    def accept (self):
        return []

    def loop(self):
        prompt()
        while True:
            rlist = [self.ss] + [sys.stdin]
            rr, rw, rx = select.select(rlist, [], [])

            for s in rr:
                #data incoming
                if s is self.ss:
                    data = s.recv(MAX_BUFSIZE)
                    if not data:
                        print '\nServer Down'
                        sys.exit(-1)
                    else:
                        self.handleIn(data)
                        prompt()
                #data from input
                else:
                    msg = sys.stdin.readline()
                    self.handleOut(msg)
                    prompt()

    #TODO handle incoming stream
    def handleIn(self, data):
        return 0

    #TODO handle outgoing stream
    def handleOut(self, msg):
        return 0

def prompt():
    sys.stdout.write('<You> ')
    sys.stdout.flush()


if __name__ == "__main__":
    # sys.exit(chat_client())

    client = None
    while True:
        try:
            print 'Starting IM Client'
            client = Client()
            client.loop()
        except KeyboardInterrupt:
                print '\n'
                #client.stop()
                try:
                    print "Press CTRL-C again within 2 sec to quit"
                    time.sleep(2)
                except KeyboardInterrupt:
                    print "CTRL-C pressed twice: Quitting!"
                    break
        except:
            logging.exception("Server ERROR")
            #if client is not (None):
            #    client.stop()
            time.sleep(10)




