# encoding: utf-8
#
# Andre Silva Santos
# Pedro Toipa Coelho

# vim setings:
# :set expandtab ts=4

import sys, socket, select, json, time, util, crypto, random


# Server address
HOST = ""  # All available interfaces
PORT = 8080  # The server port
BUFSIZE = 512 * 1024
MAX_BUFSIZE = 64 * 1024
TERMINATOR = '\n\n'
PHASE = 1

STATE_NONE = 0
STATE_CONNECTED = 1
STATE_DISCONNECTED = 2


class CS:
    def __init__(self):
        self.cipherSpec = ["ECDHE-RSA-AES256-CTR-SHA512"]
        self.key = None
        self.puk = None
        self.iv = None
        self.sk = None
        self.sig = None


class Peer:
    def __init__(self, id):
        self.id = id
        self.name = 'Peer'
        self.state = STATE_NONE
        self.cs = None
        self.rsa = None


class Client:
    def __init__(self):
        self.id = util.generate_nonce()
        self.name = 'Unknown'
        self.ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ss.settimeout(4)
        self.ciphers = ["ECDHE-RSA-AES256-CTR-SHA512"]
        self.rsa = crypto.genKeyPair('RSA')
        self.peers = {}

        try:
            self.ss.connect((HOST, PORT))
        except:
            print 'Unable to Connect'
            time.sleep(2)
            sys.exit(-1)

    def addPeer(self, pid):
        if pid in self.peers:
            print 'Already paired'
            return

        peer = Peer(pid)
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

    def serverConn(self):
        out = util.connect(1, self.name, self.id, self.ciphers, 'NONE')
        self.ss.send(json.dumps(out) + TERMINATOR)

    def loop(self):

        while True:
            rlist = [self.ss] + [sys.stdin]
            rr, rw, rx = select.select(rlist, [], [])
            for s in rr:
                # data incoming
                if s is self.ss:
                    data = s.recv(MAX_BUFSIZE)
                    if not data:
                        print '\nServer Down'
                        sys.exit(-1)
                    else:
                        self.handleIn(data)
                # data from input
                else:
                    msg = sys.stdin.readline()
                    self.handleOut(msg)

            prompt()

    def handleIn(self, data):
        reqs = self.parseReqs(data)
        for req in reqs:
            self.handleRequest(req)

    def handleOut(self, msg):
        if '<dst:' in msg:
            self.peerLink(msg)
        elif '<list>' in msg:
            self.sendList(msg)
        elif '<help>' in msg:
            self.manual()
        elif '<end:' in msg:
            self.sendDisconnect(msg)
        else:
            print 'ERROR <help> for usage'

    def sendList(self, msg):
        payload = util.lista('None')
        out = util.secure('None', payload)
        self.ss.send(json.dumps(out) + TERMINATOR)

    def peerLink(self, msg):
        dst = msg[5:9]
        msg = msg[10:]
        if dst not in self.peers:
            print 'first connection - connecting'
            self.sendConnect(dst)
        else:
            self.sendComm(dst, msg)

    #TODO encrypt
    def sendComm(self, dst, msg):
        payload = util.clientCom(self.id, dst, {'msg': msg})
        out = util.secure('none', payload)
        print msg
        self.ss.send(json.dumps(out) + TERMINATOR)

    #TODO encrypt
    def sendConnect(self, dst):
        payload = util.clientConnect(self.id, dst, 1, self.ciphers, 'none')
        out = util.secure('none', payload)
        self.ss.send(json.dumps(out) + TERMINATOR)

    def manual(self):
        print '\'<help>\' - list commands'
        print '\'<list>\' - list all clients'
        print '\'<dst:[id]>\' [msg] - send [msg] to [id]'
        print '\'<end:[id]>\' - to end connection with [id]'

    #TODO
    def sendDisconnect(self, msg):
        return

    def parseReqs(self, data):
        reqs = data.split(TERMINATOR)
        return reqs[:-1]

    #TODO negociação com o servidor
    def handleConnect(self, req):
        return

    #TODO cenas seguras e o caralho
    def handleSecure(self, request):
        if 'payload' not in request:
            print 'Secure message with missing fields'
            return

        if not isinstance(request['payload'], dict):
            request['payload'] = json.dumps(request['payload'])

        if 'type' not in request['payload'].keys():
            print 'Secure message without inner frame type'

        if request['payload']['type'] == 'list':
            self.handleList(request['payload'])
            return

        if request['payload']['type'] == 'client-connect':
            self.processConnect(request['payload']['src'], request['payload'])

        if request['payload']['type'] == 'client-com':
            self.processComm(request['payload']['src'], request['payload'])

        if not all(k in request['payload'].keys() for k in ("src", "dst")):
            return

        if not request['payload']['src'] in self.peers:
            print 'Message from unknown peer: ' + request['payload']['src']
            return

    def handleRequest(self, request):
        req = json.loads(request)

        if not isinstance(req, dict):
            return

        if 'type' not in req:
            return

        if req['type'] == 'ack':
            #print 'ack'
            return

        # Negociacao da cifra
        if req['type'] == 'connect':
            self.handleConnect(req)

        if req['type'] == 'secure':
            self.handleSecure(req)

    def handleList(self, request):
        list = []
        if 'data' not in request:
            print 'List message with missing fields'
            return

        if len(request['data']) < 2:
            print 'No other clients connected'
            return
        else:
            for i in request['data']:
                if i['id'] != self.id:
                    list.append(str(i['id'] + ' - ' + i['name']))

        print list

    #TODO encrypt
    def processConnect(self, src, request):
        if not all(k in request.keys() for k in ('ciphers', 'phase', 'src', 'dst', 'data')):
            print 'Connect message with missing fields'
            return

        if src not in self.peers.keys():
            out = util.secure('None', util.clientConnect(self.id, src, request['phase'] + 1, 'NONE', 'NONE'))
            self.ss.send(json.dumps(out) + TERMINATOR)
            self.addPeer(src)

        return

    def processComm(self, src, msg):
        print '\n' + str(src) + " : " + str(msg['data']['msg'])
        return


def prompt():
    sys.stdout.write('<You> ')
    sys.stdout.flush()


if __name__ == "__main__":
    # sys.exit(chat_client())

    client = None
    while True:
        # noinspection PyBroadException
        try:
            print 'Starting IM Client'
            client = Client()
            client.serverConn()
            client.loop()
        except KeyboardInterrupt:
            print '\n'
            # client.stop()
            try:
                print "Press CTRL-C again within 2 sec to quit"
                time.sleep(2)
            except KeyboardInterrupt:
                print "CTRL-C pressed twice: Quitting!"
                break
        except:
            print "ERROR"
            # if client is not (None):
            #    client.stop()
            time.sleep(10)
