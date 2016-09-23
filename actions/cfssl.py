
# Ansible action plugin to generate certificates securely using a remote CFSSL
# service.
#
#  * Mutual TLS auth between client and server.
#  * Certificates are generated on the master (local machine) and stored
#    in variables.
#  * Private keys never stored on local disk.
#
# This action does not execute any modules.  The certificate and private key
# are returned as part of the result.


import hashlib, json, os, re, sys, threading, traceback
from collections import namedtuple
from urlparse import urlparse

from ansible.plugins.action import ActionBase
from ansible.utils.display import Display

from concurrent.futures import Future
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from OpenSSL import SSL
from twisted.internet import defer, reactor, ssl, task
from twisted.python import threadable
from twisted.web.client import getPage


BACKEND = default_backend()
ENCODING_PEM = serialization.Encoding.PEM
FORMAT_PKCS8 = serialization.PrivateFormat.PKCS8

display = Display()
threadable.init(1)

E_HOSTPORT = 'expected HOST:PORT but got %r'
E_LOADPEM = 'failed to load %r PEM: %s'
E_SHA1ERR = '%s SHA-1 mismatch. Expected %s got %s'

TLS_OPTIONS = dict(extraCertificateOptions = dict(method = SSL.TLSv1_2_METHOD))

PEM_TYPES = (
    'CERTIFICATE',
    'PRIVATE KEY',
    'EC PRIVATE KEY',
    'RSA PRIVATE KEY',
    'DH PARAMETERS'
    )

RE_SP = re.compile('\s+', re.M)
RE_SERVICE = re.compile('[\w.-]+:\d+')
RE_PEM = re.compile(
    '-----BEGIN (' + 
    '|'.join(PEM_TYPES) + 
    ')-----\r?\n(.+?)\r?\n-----END \\1-----\r?\n?', re.DOTALL)

Pem = namedtuple('Pem', 'raw, type, bytes')


# The Twisted reactor is started on a background thread, and futures are used
# to adapt the synchronous Ansible code to the asynchronous Twisted code.
#
# Using Twisted since its TLS implementation allows establishing a mutual TLS
# client connection while passing the PEM private key and cert to OpenSSL in a
# variable instead of a disk file, since we never want the CA client's private
# key to hit the local or remote disk.
 
_REACTOR = None


def start_reactor():
    '''
    Start the reactor on a background thread so our actions are executed on
    the main thread.
    '''
    global _REACTOR
    if reactor.running:
        return
    if not _REACTOR or not _REACTOR.isAlive():
        run = lambda: reactor.run(installSignalHandlers=False)
        _REACTOR = threading.Thread(name='Reactor', target=run)
        _REACTOR.start()


def stop_reactor():
    reactor.callFromThread(reactor.stop)


def invoke(func, *args, **kw):
    '''
    Invokes a function that (may or may not) call twisted asynchronous code
    and adapts the (possibly deferred) result to a Future.
    '''
    future = Future()

    @defer.inlineCallbacks
    def adapt_future():
        try:
            res = yield defer.maybeDeferred(func, *args, **kw)
            future.set_result(res)
        except Exception as e:
            future.set_exception(e)

    reactor.callFromThread(adapt_future)
    return future


class Client(object):

    '''
    Mutual TLS CFSSL client to issue new certificates.
    '''

    def __init__(self, base_url, profile, cert_key, ca_bundle):
        self.base_url = base_url
        self.profile = profile
        self.cert_key = cert_key
        self.ca_bundle = ca_bundle

    def get_host(self):
        u = urlparse(self.base_url)
        parts = u.netloc.split(':', 1)
        return unicode(parts[0])

    @defer.inlineCallbacks
    def getcert(self, csr):
        host = self.get_host()
        trustRoot = ssl.trustRootFromCertificates(self.ca_bundle)
        opts = ssl.optionsForClientTLS(host, trustRoot, self.cert_key, **TLS_OPTIONS)
        req = {'request': csr, 'profile': self.profile}
        url = self.base_url + '/api/v1/cfssl/newcert'
        res = yield getPage(url,
            contextFactory=opts,
            method='POST',
            postdata=json.dumps(req))
        defer.returnValue(res)


def pem_split(s):
    return list(Pem(m.group(0), m.group(1), m.group(2)) for m in RE_PEM.finditer(s))


def fail(msg):
    return dict(failed=True, msg=msg)


def format_msg(rec):
    r = ''
    for m in rec.get('messages', []):
        r += '%s: %s\n' % (m.get('code'), m.get('message'))
    return r


def getdeep(d, key, defval=''):
    for k in key.split('.'):
        d = d.get(k, {})
    return d if d else defval


def sha1(data):
    return hashlib.sha1(data).hexdigest()[1:].upper()


def encrypt_private_key(key_pem, passphrase):
    key_pem = key_pem.encode('ascii')
    passphrase = passphrase.encode('utf-8')
    key = serialization.load_pem_private_key(key_pem, None, BACKEND)
    return key.private_bytes(ENCODING_PEM, FORMAT_PKCS8,
            serialization.BestAvailableEncryption(passphrase))


def extract_certkey(rec):
    r = rec.get('result', {})

    # extract the cert, key and csr values
    cert = getdeep(r, 'certificate', '')
    key = getdeep(r, 'private_key', '')
    csr = getdeep(r, 'certificate_request', '')

    # TODO: Validate the signatures on the certificate and csr.

    return (cert, key, csr), None


class ActionModule(ActionBase):

    ARGS = set(['service', 'auth', 'profile', 'csr'])
    AUTH_ARGS = set(['cert', 'key', 'cacert'])

    TRANSFER_FILES = False

    def __init__(self, *n, **kw):
        # force 'no_log' to be true, since we want to return the private key as
        # a result variable and don't ever want it logged.
        # TODO: clearner way to do this?
        ctx = kw.get('play_context')
        if ctx:
            ctx.no_log = True
        ActionBase.__init__(self, *n, **kw)

    def arg(self, name):
        return self._task.args.get(name, None)

    def check_args(self, names, collection):
        for arg in names:
            if arg not in collection:
                return fail('%r is a required argument' % arg)

    def load_file(self, path):
        root = self._loader.get_basedir()
        if self._task._role is not None:
            root = self._task._role._role_path
        realpath = self._loader.path_dwim_relative(root, 'files', path)
        return open(realpath, 'rb').read()

    def run(self, tmp=None, task_vars=None):
        try:
            return self._run(tmp, task_vars)
        except Exception as e:
            # since this action always runs in no_log=True mode, manually
            # print the real exception, if any.
            display.error(traceback.format_exc())
            return fail('Failed!')

    def _run(self, tmp=None, task_vars=None):
        err = self.check_args(self.ARGS, self._task.args)
        if err:
            return err

        getarg = lambda n, d=None: self._task.args.get(n, d)

        service = getarg('service')
        auth = getarg('auth')
        profile = getarg('profile')
        csr_arg = getarg('csr')
        show = getarg('show', False)
        if isinstance(show, basestring):
            show = show in ('yes','true','1')

        # optional passphrase to protect generated private key
        passphrase = getarg('passphrase')

        err = self.check_args(self.AUTH_ARGS, auth)
        if err:
            return err

        cert = auth.get('cert')
        key = auth.get('key')
        cacert = auth.get('cacert')

        # validate some args
        if not RE_SERVICE.match(service):
            return fail(E_SERVICE % service)
        service = service.encode('utf-8')

        try:
            cert_key = ssl.PrivateCertificate.loadPEM(cert + '\n' + key)
        except Exception as e:
            return fail(E_LOADPEM % ('cert/key', traceback.format_exc()))

        try:
            ca_bundle = [ssl.Certificate.loadPEM(p.raw) for p in pem_split(cacert)]
        except Exception as e:
            return fail(E_LOADPEM % ('cacert', traceback.format_exc()))

        if isinstance(csr_arg, dict):
            # csr definition is inline yaml object
            csr = csr_arg
        elif isinstance(csr_arg, basestring):
            # assume csr string is a path to a disk location
            data = self.load_file(csr_arg)
            csr = json.loads(data)

        # build the client talking to the service url
        base_url = 'https://%s' % service
        client = Client(base_url, profile, cert_key, ca_bundle)

        # contact the cfssl service to issue a new certificate
        try:
            start_reactor()
            data = invoke(client.getcert, csr).result()
            record = json.loads(data)
        finally:
            stop_reactor()

        # extract warning messages, if any, from cfssl result
        msg = format_msg(record)
        if msg:
            display.warning('CFSSL MESSAGES :' + msg)

        ck, err = extract_certkey(record)
        if err:
            msg = 'FAILED TO EXTRACT VALUES: %s' % err
            display.error(msg)
            return fail(msg)

        cert, key, csr = ck
        if not cert:
            return fail('Failed to generate CERTIFICATE')
        if not key:
            return fail('Failed to generate PRIVATE KEY')
        if not csr:
            return fail('Failed to generate CSR')

        # optional passphrase encryption with PKCS#8 AES256 CBC
        if passphrase:
            key = encrypt_private_key(key, passphrase)

        if show:
            display.display(cert + '\n\n' + key + '\n\n' + csr)

        # return the certificate and key
        return dict(cert = cert, key = key, csr = csr)

