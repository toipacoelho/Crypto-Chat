# encoding: utf-8
# -*- coding: utf-8 -*-
#
# Andre Silva Santos
# Pedro Toipa Coelho

# vim setings:
# :set expandtab ts=4

import sys, socket, select, json, time, util, crypto, random, base64
import cc_util as cc


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
        try:
            self.name = cc.get_subjdata_from_cert(cc.get_certificate())
            print self.name
        except:
            self.name = 'Unknown'
        self.ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ss.settimeout(4)
        self.ciphers = ["ECDHE-RSA-AES256-CTR-SHA512"]
        self.rsa = crypto.genKeyPair('RSA')
        self.peers = {}
        self.nounces = []

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
        try:
            cert = base64.b64encode(cc.get_certificate())
            puk = base64.b64encode(cc.cert_puk(cc.get_certificate()))
            nounce = util.generate_nonce()
            sign = base64.b64encode(cc.sign(nounce))
        except:
            cert = ""
            puk = ""
            nounce = ""
            sign = ""
        out = util.connect(1, base64.b64encode(self.name), self.id, self.ciphers, {"cert": cert, "puk": puk, "nounce": str(nounce), "sign": sign})
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

    #TODO cenas seguras (M1)
    def sendComm(self, dst, msg):
        try:
            sig = base64.b64encode(cc.sign(msg))
            puk = base64.b64encode(cc.cert_puk(cc.get_certificate()))
        except:
            sig = base64.b64encode("")
            puk = base64.b64encode("")
        nounce = util.generate_nonce()
        self.nounces.append(nounce)
        payload = util.clientCom(self.id, dst, {'msg': msg, 'sign': sig, 'puk': puk, 'nounce': nounce})
        out = util.secure('none', payload)
        self.ss.send(json.dumps(out) + TERMINATOR)
        print "My nounce: ", nounce

    #TODO cenas seguras (M1)
    def sendConnect(self, dst):
        payload = util.clientConnect(self.id, dst, 1, self.ciphers, 'none')
        out = util.secure('none', payload)
        self.ss.send(json.dumps(out) + TERMINATOR)

    def manual(self):
        print '\'<help>\' - list commands'
        print '\'<list>\' - list all clients'
        print '\'<dst:[id]>\' [msg] - send [msg] to [id]'
        print '\'<end:[id]>\' - to end connection with [id]'

    def sendDisconnect(self, msg):
        dst = msg[5:9]
        msg = msg[10:]
        if dst in self.peers.keys():
            out = util.secure('None', util.clientDisconnect(self.id, dst, 'None'))
            self.ss.send(json.dumps(out) + TERMINATOR)
            self.delPeer(dst)
        return

    def parseReqs(self, data):
        reqs = data.split(TERMINATOR)
        return reqs[:-1]

    #TODO negociação com o servidor (M1)
    def handleConnect(self, req):
        if crypto.verSELFcert(req['data']['server_cert']):
            print "Connected to trusted server"
        else:
            print "server not trusted, be aware"
            return

    #TODO cenas seguras (M1)
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

        if request['payload']['type'] == 'ack':
            self.processAck(request['payload'])

        if request['payload']['type'] == 'client-connect':
            self.processConnect(request['payload']['src'], request['payload'])

        if request['payload']['type'] == 'client-com':
            self.processComm(request['payload']['src'], request['payload'])

        if request['payload']['type'] == 'client-disconnect':
            self.processDisconnect(request['payload']['src'], request['payload'])

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
                    name = base64.b64decode(i['name'])
                    try:
                        list.append(str(i['id']) + ' - ' + str(name))
                    except Exception as e:
                        print e
                        list.append(str(i['id']))

        print list

    #TODO cenas seguras (M1)
    def processConnect(self, src, request):
        if not all(k in request.keys() for k in ('ciphers', 'phase', 'src', 'dst', 'data')):
            print 'Connect message with missing fields'
            return

        if src not in self.peers.keys():
            out = util.secure('None', util.clientConnect(self.id, src, request['phase'] + 1, 'NONE', 'NONE'))
            self.ss.send(json.dumps(out) + TERMINATOR)
            self.addPeer(src)

        return

    #TODO cenas seguras (M1)
    def processComm(self, src, msg):
        self.sendAck(src, msg['data']['nounce'])
        sign = base64.b64decode(msg['data']['sign'])
        puk = base64.b64decode(msg['data']['puk'])

        try:
            if cc.vercompuk(puk, str(msg['data']['msg']), sign):
                print "[trusted]" + str(src) + " : " + str(msg['data']['msg'])
            else:
                print "[untrusted]" + str(src) + " : " + str(msg['data']['msg'])
        except:
            print "[unsigned]" + str(src) + " : " + str(msg['data']['msg'])
        return

    #TODO cenas seguras (M1)
    def sendAck(self, src, nounce):
        try:
            cert = base64.b64encode(cc.get_certificate())
            puk = base64.b64encode(cc.cert_puk(cc.get_certificate()))
            sign = base64.b64encode(cc.sign(nounce))
            cc_flag = str(1)
        except Exception as e:
            cert = ""
            puk = ""
            sign = ""
            cc_flag = str(0)
        payload = util.ack(self.id, src, {'nounce': nounce, 'cc_flag': cc_flag, 'cert': cert, 'sign': sign, 'puk': puk})
        out = util.secure('None', payload)
        self.ss.send(json.dumps(out) + TERMINATOR)

    def processAck(self, req):
        cert = base64.b64decode(req['data']['cert'])
        puk = base64.b64decode(req['data']['puk'])
        nounce = str(req['data']['nounce'])
        sign = base64.b64decode(req['data']['sign'])

        if nounce not in self.nounces:
            print "Ups, something not right with your partner ack, run you fool"
            return

        if req['data']['cc_flag'] == 1:
            try:
                if cc.vercompuk(puk, str(nounce), sign) and cc.ver_cert(cert):
                    print cc.get_subjdata_from_cert(cert), " ack: ", req['data']['nounce']
            except:
                pass
        else:
            print "Ack: ", req['data']['nounce']

        self.nounces.remove(nounce)

    def processDisconnect(self, src, msg):
        if src in self.peers.keys():
            out = util.secure('None', util.clientDisconnect(self.id, src, 'None'))
            self.ss.send(json.dumps(out) + TERMINATOR)
            self.delPeer(src)
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
        except Exception as e:
            print "ERROR", e
            # if client is not (None):
            #    client.stop()
            time.sleep(10)
