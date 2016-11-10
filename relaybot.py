from twisted.words.protocols import irc
from twisted.internet import reactor, protocol, ssl
from twisted.internet.protocol import ReconnectingClientFactory, ServerFactory
from twisted.python import log, reflect, util
from twisted.internet.endpoints import clientFromString, serverFromString
from twisted.internet.error import VerifyError, CertificateError
from twisted.internet.defer import Deferred, succeed
from twisted.internet.task import LoopingCall
from twisted.application import service
from twisted.web import client, http_headers, iweb, resource, server
from zope.interface import implementer
from hashlib import md5
from OpenSSL import SSL, crypto
from signal import signal, SIGINT
from ConfigParser import SafeConfigParser
import re, sys, itertools, json

#
# RelayBot is a derivative of http://code.google.com/p/relaybot/
#

log.startLogging(sys.stdout)

__version__ = "0.1"
application = service.Application("RelayBot")

_sessionCounter = itertools.count().next

def main():
    config = SafeConfigParser()
    config.read("relaybot.config")
    defaults = config.defaults()

    # Webhook stuff
    webhooks = resource.Resource()
    pool = client.HTTPConnectionPool(reactor)
    agent = client.Agent(reactor, pool=pool)

    for section in config.sections():

        def get(option):
            if option in defaults or config.has_option(section, option):
                return config.get(section, option) or defaults[option]
            else:
                return None

        options = {'servername': section}
        for option in [ "timeout", "host", "port", "nick", "channel", "channels", "heartbeat", "password", "username", "realname", "mode", "ssl", "fingerprint", "nickcolor", "topicsync" ]:
            options[option] = get(option)

        mode = get("mode")

        #Not using endpoints pending http://twistedmatrix.com/trac/ticket/4735
        #(ReconnectingClientFactory equivalent for endpoints.)
        factory = None
        if mode == "Default":
            factory = RelayFactory
        elif mode == "FLIP":
            factory = FLIPFactory
        elif mode == "NickServ":
            factory = NickServFactory
            options["nickServPassword"] = get("nickServPassword")
        elif mode == "ReadOnly":
            factory = ReadOnlyFactory
            options["nickServPassword"] = get("nickServPassword")
        # RelayByCommand: only messages with <nickname>: will be relayed. 
        elif mode == "RelayByCommand":
            factory = CommandFactory
        elif mode == "Webhooks":
            options['webhookNonce'] = get('webhookNonce')
            options['outgoingWebhook'] = get('outgoingWebhook')
            webhooks.putChild(options['webhookNonce'], Webhook(agent, options))
            continue

        factory = factory(options)
        if options['ssl'] == "True":
            if options['fingerprint']:
                ctx = certoptions(fingerprint=options['fingerprint'], verifyDepth=0)
                reactor.connectSSL(options['host'], int(options['port']), factory, ctx, int(options['timeout']))
            else:
                reactor.connectSSL(options['host'], int(options['port']), factory, ssl.ClientContextFactory(), int(options['timeout']))
        else:
            reactor.connectTCP(options['host'], int(options['port']), factory, int(options['timeout']))

    # Start incoming webhook server
    if 'webhook' in defaults:
        serverFromString(reactor, defaults['webhook']).listen(server.Site(webhooks))

    reactor.callWhenRunning(signal, SIGINT, handler)

class certoptions(object):
    _context = None
    _OP_ALL = getattr(SSL, 'OP_ALL', 0x0000FFFF)
    _OP_NO_TICKET = 0x00004000
    method = SSL.TLSv1_METHOD

    def __init__(self, privateKey=None, certificate=None, method=None, verify=False, caCerts=None, verifyDepth=9, requireCertificate=True, verifyOnce=True, enableSingleUseKeys=True, enableSessions=True, fixBrokenPeers=False, enableSessionTickets=False, fingerprint=True):
        assert (privateKey is None) == (certificate is None), "Specify neither or both of privateKey and certificate"
        self.privateKey = privateKey
        self.certificate = certificate
        if method is not None:
            self.method = method

        self.verify = verify
        assert ((verify and caCerts) or
            (not verify)), "Specify client CA certificate information if and only if enabling certificate verification"

        self.caCerts = caCerts
        self.verifyDepth = verifyDepth
        self.requireCertificate = requireCertificate
        self.verifyOnce = verifyOnce
        self.enableSingleUseKeys = enableSingleUseKeys
        self.enableSessions = enableSessions
        self.fixBrokenPeers = fixBrokenPeers
        self.enableSessionTickets = enableSessionTickets
        self.fingerprint = fingerprint

    def __getstate__(self):
        d = self.__dict__.copy()
        try:
            del d['_context']
        except KeyError:
            pass
        return d


    def __setstate__(self, state):
        self.__dict__ = state


    def getContext(self):
        if self._context is None:
            self._context = self._makeContext()
        return self._context


    def _makeContext(self):
        ctx = SSL.Context(self.method)

        if self.certificate is not None and self.privateKey is not None:
            ctx.use_certificate(self.certificate)
            ctx.use_privatekey(self.privateKey)
            ctx.check_privatekey()

        verifyFlags = SSL.VERIFY_NONE
        if self.verify or self.fingerprint:
            verifyFlags = SSL.VERIFY_PEER
            if self.requireCertificate:
                verifyFlags |= SSL.VERIFY_FAIL_IF_NO_PEER_CERT
            if self.verifyOnce:
                verifyFlags |= SSL.VERIFY_CLIENT_ONCE
            if self.caCerts:
                store = ctx.get_cert_store()
                for cert in self.caCerts:
                    store.add_cert(cert)

        def _verifyCallback(conn, cert, errno, depth, preverify_ok):
            if self.fingerprint:
                digest = cert.digest("sha1")
            if digest != self.fingerprint:
                log.msg("Remote server fingerprint mismatch. Got: %s Expect: %s" % (digest, self.fingerprint))
                return False
            else:
                log.msg("Remote server fingerprint match: %s " % (digest))
                return True
            return preverify_ok

        ctx.set_verify(verifyFlags, _verifyCallback)

        if self.verifyDepth is not None:
            ctx.set_verify_depth(self.verifyDepth)

        if self.enableSingleUseKeys:
            ctx.set_options(SSL.OP_SINGLE_DH_USE)

        if self.fixBrokenPeers:
            ctx.set_options(self._OP_ALL)

        if self.enableSessions:
            sessionName = md5("%s-%d" % (reflect.qual(self.__class__), _sessionCounter())).hexdigest()
            ctx.set_session_id(sessionName)

        if not self.enableSessionTickets:
            ctx.set_options(self._OP_NO_TICKET)

        return ctx

class Communicator:
    def __init__(self):
        self.protocolInstances = {}

    def register(self, protocol):
        self.protocolInstances[protocol.identifier] = protocol

    def isRegistered(self, protocol):
        return protocol.identifier in self.protocolInstances

    def unregister(self, protocol):
        if protocol.identifier not in self.protocolInstances:
            log.msg("No protocol instance with identifier %s."%protocol.identifier)
            return
        del self.protocolInstances[protocol.identifier]

    def relay(self, protocol, channel, message):
        for identifier in self.protocolInstances.keys():
            if identifier == protocol.identifier:
                continue
            instance = self.protocolInstances[identifier]
            instance.say(channel, message)

    def relayTopic(self, protocol, channel, newTopic):
        for identifier in self.protocolInstances.keys():
            if identifier == protocol.identifier:
                continue
            instance = self.protocolInstances[identifier]
            instance.topic(channel, newTopic)

#Global scope: all protocol instances will need this.
communicator = Communicator()

class IRCRelayer(irc.IRCClient):

    def __init__(self, config):
        self.servername = config['servername']
        self.network = config['host']
        self.password = config['password']
        self.channels = config['channels']
        self.nickname = config['nick']
        self.identifier = config['identifier']
        self.heartbeatInterval = float(config['heartbeat'])
        self.username = config['username']
        self.realname = config['realname']
        self.mode = config['mode']
        self.nickcolor = config['nickcolor']
        self.topicsync = config['topicsync']

        # IRC RFC: https://tools.ietf.org/html/rfc2812#page-4
        if len(self.nickname) > 9:
            log.msg("Nickname %s is %d characters long, which exceeds the RFC maximum of 9 characters. This may cause connection problems."%(self.nickname, len(self.nickname)))

        # Backward compatibility with deprecated single-channel setting
        if not self.channels:
            self.channels = config['channel']

        # Read comma separated string as list
        self.channels = [channel.strip() for channel in self.channels.split(',')]
        log.msg("IRC Relay created. Name: %s | Host: %s | Channels: %s" % (
            self.nickname, self.network, ",".join(self.channels)))

    def formatUsername(self, username):
        return username.split("!")[0]

    def relay(self, channel, message):
        communicator.relay(self, channel, message)

    def relayTopic(self, channel, newTopic):
        communicator.relayTopic(self, channel, newTopic)

    def joinChannel(self, channel):
        self.join(channel, "")

    def joinChannels(self):
        [self.joinChannel(channel) for channel in self.channels]

    def signedOn(self):
        log.msg("[%s] Connected to network."%self.network)
        self.startHeartbeat()
        self.joinChannels()

    def connectionLost(self, reason):
        log.msg("[%s] Connection lost, unregistering."%self.network)
        communicator.unregister(self)

    def joined(self, channel):
        log.msg("Joined channel %s, registering."%channel)
        communicator.register(self)

    def formatMessage(self, message):
        return message.replace(self.nickname + ": ", "", 1)

    def formatNick(self, user):
        nick = "[" + self.servername + "/" + self.formatUsername(user) + "]"
        if self.nickcolor == "True":
            nick = "[" + self.servername + "/\x0303" + self.formatUsername(user) + "\x03]"
        return nick

    def privmsg(self, user, channel, message):
        if self.mode != "RelayByCommand":
            self.relay(channel, "%s %s"%(self.formatNick(user), message))
        elif message.startswith(self.nickname + ':'):
            self.relay(channel, "%s %s"%(self.formatNick(user), self.formatMessage(message)))

    def kickedFrom(self, channel, kicker, message):
        log.msg("Kicked by %s. Message \"%s\""%(kicker, message))
        communicator.unregister(self)

    def action(self, user, channel, message):
        if self.mode != "RelayByCommand":
            self.relay(channel, "%s %s"%(self.formatNick(user), message))

    def topicUpdated(self, user, channel, newTopic):
        if self.mode != "RelayByCommand":
            self.topic(user, channel, newTopic)

    def topic(self, user, channel, newTopic):
        if self.topicsync == "True":
            self.relayTopic(channel, newTopic)

class RelayFactory(ReconnectingClientFactory):
    protocol = IRCRelayer
    #Log information which includes reconnection status.
    noisy = True

    def __init__(self, config):
        config["identifier"] = "{0}{1}{2}".format(config["host"], config["port"], config["channel"])
        self.config = config

    def buildProtocol(self, addr):
        #Connected - reset reconnect attempt delay.
        self.maxDelay = 900
        x = self.protocol(self.config)
        x.factory = self
        return x

#Remove the _<numbers> that FLIP puts on the end of usernames.
class FLIPRelayer(IRCRelayer):
    def formatUsername(self, username):
        return re.sub("_\d+$", "", IRCRelayer.formatUsername(self, username))

class FLIPFactory(RelayFactory):
    protocol = FLIPRelayer

class NickServRelayer(IRCRelayer):
    NickServ = "nickserv"
    NickPollInterval = 30

    def signedOn(self):
        log.msg("[%s] Connected to network."%self.network)
        self.startHeartbeat()
        self.joinChannels()
        self.checkDesiredNick()

    def checkDesiredNick(self):
        """
        Checks that the nick is as desired, and if not attempts to retrieve it with
        NickServ GHOST and trying again to change it after a polling interval.
        """
        if self.nickname != self.desiredNick:
            log.msg("[%s] Using GHOST to reclaim nick %s."%(self.network, self.desiredNick))
            self.msg(NickServRelayer.NickServ, "GHOST %s %s"%(self.desiredNick, self.password))
            # If NickServ does not respond try to regain nick anyway.
            self.nickPoll.start(self.NickPollInterval)

    def regainNickPoll(self):
        if self.nickname != self.desiredNick:
            log.msg("[%s] Reclaiming desired nick in polling."%(self.network))
            self.setNick(self.desiredNick)
        else:
            log.msg("[%s] Have desired nick."%(self.network))
            self.nickPoll.stop()

    def nickChanged(self, nick):
        log.msg("[%s] Nick changed from %s to %s."%(self.network, self.nickname, nick))
        self.nickname = nick
        self.checkDesiredNick()

    def noticed(self, user, channel, message):
        log.msg("[%s] Recieved notice \"%s\" from %s."%(self.network, message, user))
        #Identify with nickserv if requested
        if IRCRelayer.formatUsername(self, user).lower() == NickServRelayer.NickServ:
            msg = message.lower()
            if msg.startswith("this nickname is registered"):
                log.msg("[%s] Password requested; identifying with %s."%(self.network, NickServRelayer.NickServ))
                self.msg(NickServRelayer.NickServ, "IDENTIFY %s"%self.password)
            elif msg == "ghost with your nickname has been killed." or msg == "ghost with your nick has been killed.":
                log.msg("[%s] GHOST successful, reclaiming nick %s."%(self.network,self.desiredNick))
                self.setNick(self.desiredNick)
            elif msg.endswith("isn't currently in use."):
                log.msg("[%s] GHOST not needed, reclaiming nick %s."%(self.network,self.desiredNick))
                self.setNick(self.desiredNick)

    def __init__(self, config):
        IRCRelayer.__init__(self, config)
        self.password = config['nickServPassword']
        self.desiredNick = config['nick']
        self.nickPoll = LoopingCall(self.regainNickPoll)

class ReadOnlyRelayer(NickServRelayer):
    pass

class CommandRelayer(IRCRelayer):
    pass

class ReadOnlyFactory(RelayFactory):
    protocol = ReadOnlyRelayer

class NickServFactory(RelayFactory):
    protocol = NickServRelayer

class CommandFactory(RelayFactory):
    protocol = CommandRelayer

@implementer(iweb.IBodyProducer)
class StringProducer(object):
    def __init__(self, body):
        self.body = body
        self.length = len(body)

    def startProducing(self, consumer):
        consumer.write(self.body)
        return succeed(None)

    def pauseProducing(self):
        pass

    def stopProducing(self):
        pass

class Webhook(resource.Resource):
    def __init__(self, agent, config):
        self.agent = agent
        self.servername = config['servername']
        self.identifier = 'Webhook:%s' % config['webhookNonce']
        self.outgoingWebhook = config['outgoingWebhook']
        self.nickcolor = config['nickcolor']

        communicator.register(self)

    def render_POST(self, request):
        """
        Process the contents of a request (i.e. a post from Rocket.Chat's
        webhook service)
        """
        action = request.getHeader("X-IRC-Action")
        obj = json.loads(request.content.read())

        if action == 'say':
            user = str(obj['username'])
            channel = str(obj['channel'])
            message = str(obj['message'])
            self.relay(channel, "%s %s"%(self.formatNick(user), message))

    def formatUsername(self, username):
        return username.split("!")[0]

    def formatNick(self, user):
        nick = "[" + self.servername + "/" + self.formatUsername(user) + "]"
        if self.nickcolor == "True":
            nick = "[" + self.servername + "/\x0303" + self.formatUsername(user) + "\x03]"
        return nick

    def relay(self, channel, message):
        communicator.relay(self, channel, message)

    def relayTopic(self, channel, newTopic):
        communicator.relayTopic(self, channel, newTopic)

    def post(self, action, user, channel, message):
        obj = {
            'username': user,
            'channel': channel,
            'message': message,
        }
        d = self.agent.request(
            'POST',
            self.outgoingWebhook,
            http_headers.Headers({
                'Content-Type': ['application/json'],
                'X-IRC-Action': [action],
            }),
            StringProducer(json.dumps(obj)))
        def cbResponse(response):
            log.msg('Outgoing webhook response: %d' % response.code)
        d.addCallback(cbResponse)

    def say(self, channel, message, length=None):
        if self.outgoingWebhook:
            user, msg = message.split(' ', 1)
            self.post('say', user, channel, msg)

    def topic(self, user, channel, newTopic):
        pass

def handler(signum, frame):
    reactor.stop()

#Main if run as script, builtin for twistd.
if __name__ in ["__main__", "__builtin__"]:
        main()
