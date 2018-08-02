#!/usr/bin/env python3

# CERT Keyfinder
#
# Copyright 2018 Carnegie Mellon University. All Rights Reserved.
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS"
# BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER
# INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED
# FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM
# FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Released under a MIT (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu for full terms.
# [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see
#  Copyright notice for non-US Government use and distribution.
#
# DM18-0850

import sys
import os
import sys
import re

if sys.version_info[0] == 2:
    print('Python 3.x is recommended for best Unicode compatibility')
    try:
        import subprocess32 as subprocess
    except ImportError:
        print('subprocess32 library not found. Please install this package for proper functionality.')
else:
    import subprocess
import argparse
import shutil
import json
import struct
import androapkinfo
import zipfile
import base64
from pprint import pformat
import tempfile
import logging
import binascii
import gc

try:
    from urllib2 import urlopen
except ImportError:
    from urllib.request import urlopen
import hashlib
try:
    from OpenSSL import crypto
    from OpenSSL.crypto import FILETYPE_PEM
except ImportError:
    print('PyOpenSSL library not found.  Key processing capabilities will be limited.')

try:
    import magic
except ImportError:
    print('magic library not found.  Please install this package for proper functionality.')

b4 = struct.Struct('>L')  # unsigned
logger = logging.getLogger()
FNULL = open(os.devnull, 'w')
# Simple regex to detect base64 data
b64re = re.compile('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')


def get_magic(filename):
    magictype = None
    try:
        # filemagic
        with magic.Magic() as m:
            try:
                magictype = m.id_filename(filename)
            except magic.api.MagicError:
                logger.debug('Error determining magic of file: %s' % filename)
    except AttributeError:
        # python-magic
        try:
            magictype = magic.from_file(filename)
        except:
            logger.debug('Error determining magic of file: %s' % filename)

    return magictype


def getasn(keydata):
    logger.debug('getting ASN1...')
    parsed = None
    isasn1 = False
    tmpkey = tempfile.NamedTemporaryFile(suffix='.key').name
    if keydata:
        try:
            # Might be a string
            keydata = keydata.encode()
        except AttributeError:
            # Already bytes
            pass
        except UnicodeDecodeError:
            try:
                keydata = keydata.decode('utf-8').encode('utf-8')
            except:
                pass
        with open(tmpkey, 'wb') as wp:
            wp.write(keydata)
    try:
        parsed = subprocess.check_output(
            ['openssl', 'asn1parse', '-inform', 'der', '-in', tmpkey], stderr=FNULL).decode('utf-8',
                                                                                            'backslashreplace')
        os.unlink(tmpkey)
        for line in parsed.splitlines():
            if 'prim: ' in line and 'prim: EOC' not in line and ':BAD' not in line:
                # Should be ASN1 data
                if not isasn1:
                    logger.debug('"%s" Looks like legit ASN1 data' % line)
                    isasn1 = True
    except subprocess.CalledProcessError:
        os.unlink(tmpkey)

    if not isasn1:
        parsed = None

    return parsed


def validasn(keyfile):
    try:
        parsed = subprocess.check_output(
            ['openssl', 'asn1parse', '-inform', 'der', '-in', keyfile], stderr=FNULL).decode('utf-8',
                                                                                             'backslashreplace')
        if 'prim: OBJECT' in parsed:
            # logger.debug(parsed)
            return True
        else:
            return False
    except subprocess.CalledProcessError:
        return False


def is_b64(data):
    # logger.debug('Checking if %s is b64' % type(data))
    # logger.debug(data)
    if len(data) > 1:
        try:
            data = data.decode('utf-8', 'backslashreplace').replace('\n', '').replace('\r', '')
        except TypeError:
            logger.debug('UTF-8 decode error')
            pass
        # logger.debug('"%s"' % data)
        m = re.match(b64re, data)
        if m:
            logger.debug('It is base64!')
            return True
        else:
            logger.debug('It is not base64.')
            return False
    else:
        logger.debug('Zero-length file!')
        return False


def decode_b64(keyfile, keydata):
    if is_b64(keydata):
        try:
            decoded_keydata = base64.b64decode(keydata)
            # logger.debug('%s IS base64!' % keyfile)
            # logger.debug(decoded_keydata)
            return True, decoded_keydata
        except binascii.Error:
            logger.debug('%s is surprisingly NOT base64!' % keyfile)
            return False, keydata
    else:
        # logger.debug('%s is NOT base64!' % keyfile)
        return False, keydata


def output_reader(proc, outq):
    # Thread worker for reading subprocess stdout
    for line in iter(proc.stdout.readline, b''):
        outq.put(line.decode('utf-8', 'backslashreplace'))


def changejkspassword(jksfilepath):
    jksoutfile = None
    logger.debug('Changing the password for %s' % jksfilepath)

    if os.path.exists(jksfilepath):
        jksoutfile = tempfile.NamedTemporaryFile(suffix='.jks').name
        if not os.path.exists(jksoutfile):
            try:
                subprocess.check_call(['java', 'ChangePassword', jksfilepath, jksoutfile], stdout=FNULL, stderr=FNULL)
                logger.debug('Password changed!')
            except subprocess.CalledProcessError:
                logger.debug('Error changing password of %s' % jksfilepath)
                jksoutfile = None
    return jksoutfile


def parsekeystorecontents(keystorecontents):
    keydict = {}
    if keystorecontents:
        # logger.debug('Parsing %s' % bkscontents)
        try:
            keystorecontents = keystorecontents.decode('utf-8', 'backslashreplace')
        except TypeError:
            # Python 2.7
            pass
        keydict['type'] = ''
        currententry = None
        keydict['keystoretext'] = keystorecontents
        if 'Entry type: PrivateKeyEntry' in keystorecontents or 'Entry type: SecretKeyEntry' in keystorecontents:
            keydict['private'] = True
            keydict['iskey'] = True
        if 'Entry type: trustedCertEntry' in keystorecontents:
            keydict['iscert'] = True

        for line in keystorecontents.splitlines():
            line = line.rstrip()
            # logger.debug('"%s"' % line)
            if 'Entry type: PrivateKeyEntry' in line or 'Entry type: SecretKeyEntry' in line:
                # logger.debug('*** We have a key! ***')
                currententry = 'key'
            elif 'Entry type: trustedCertEntry' in line:
                # logger.debug('*** We have a cert! ***')
                currententry = 'cert'
            if line == '*******************************************':
                # logger.debug('*** We are between entries! ***')
                currententry = None
            if currententry == 'key':
                if '\t SHA256: ' in line and 'certhash' not in keydict:
                    # We have a certificate hash for a private key
                    # BKS includes entire cert chain, so stop at first one.
                    # logger.debug('*** We have a key certificate hash! ***')
                    sha256 = line.replace('\t SHA256: ', '').replace(':', '').lower()
                    keydict['certhash'] = sha256
                    foundcrt, url = checkcrt(sha256)
                    if foundcrt:
                        logger.info('-=-= This key is in CRT.SH! =-=-')
                        keydict['crt'] = url

    return keydict


def getbksversion(bksfilepath):
    logger.debug('Checking bksfilepath: "%s"' % bksfilepath)
    version = 'UNKNOWN'
    if os.path.exists(bksfilepath):
        with open(bksfilepath, 'rb') as f:
            binver = f.read(4)
        # logger.debug(binver)
        if len(binver) == 4:
            version = b4.unpack(binver)[0]
    return version


def get_keyhash(keyfile, encoding='pem', pw=''):
    if pw is None:
        # Revert back to empty string if no password
        pw = ''
    logger.debug('* Getting sha256 of key %s with password "%s"' % (keyfile, pw))
    sha256 = None
    if os.path.exists(keyfile):
        if encoding == 'pem':
            try:
                pkey_der = subprocess.check_output(
                    ['openssl', 'pkey', '-in', keyfile, '-pubout', '-outform', 'der', '-passin', str('pass:%s' % pw)],
                    timeout=2, stderr=FNULL)
                sha256 = hashlib.sha256(pkey_der).hexdigest()
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                logger.debug('%s Bad pass!' % keyfile)

        else:
            asndata = getasn(keyfile)
            if asndata:
                if 'rsaEncryption' in asndata and 'prim: OCTET STRING' in asndata:
                    logger.debug('Trying password %s on %s' % (pw, keyfile))
                    try:
                        pkey_der = subprocess.check_output(
                            ['openssl', 'pkey', '-inform', 'der', '-in', keyfile, '-pubout', '-outform', 'der',
                             '-passin', str('pass:%s' % pw)], timeout=2, stderr=FNULL)
                        sha256 = hashlib.sha256(pkey_der).hexdigest()
                        logger.debug('%s sha256: %s' % (keyfile, sha256))
                    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                        logger.debug('%s Bad pass!' % keyfile)
            else:
                logger.debug('%s is not a DER' % keyfile)

    return sha256


def get_sha256(keyfile, keydata, encoding='pem'):
    logger.debug('Analyzing and getting sha256...')
    keydict = {}
    tmpkey = tempfile.NamedTemporaryFile(suffix='.key').name
    if keydata:
        with open(tmpkey, 'wb') as wp:
            wp.write(keydata)

        if encoding == 'pem':
            logger.debug('PEM encoded key...')

            try:
                pkey_der = subprocess.check_output(
                    ['openssl', 'pkey', '-in', tmpkey, '-pubout', '-outform', 'der', '-passin', 'pass:'],
                    timeout=2, stderr=FNULL)
                sha256 = hashlib.sha256(pkey_der).hexdigest()
                keydict['protected'] = False
                keydict['keyhash'] = sha256
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                keydict['protected'] = True
                keydict['keyhash'] = None
                logger.debug('%s Bad pass!' % keyfile)

        else:
            asndata = getasn(keydata)
            if asndata:
                logger.debug('DER encoded key...')
                keydict['asn1'] = asndata
                keydict['encoding'] = 'der'
                logger.debug('%s ASNDATA:' % keyfile)
                if 'X509' in asndata:
                    logger.debug('Found DER CERTIFICATE: %s' % keyfile)
                    keydict['iscert'] = True
                    keydict['type'] = 'certificate'
                    x509text = decodex509(keydata, encoding='der')
                    keydict['x509text'] = x509text
                    keydict['private'] = False
                elif 'OBJECT            :commonName' in asndata:
                    logger.debug('Found DER CSR: %s' % keyfile)
                    keydict['type'] = 'csr'
                elif 'rsaEncryption' in asndata and 'prim: OCTET STRING' in asndata:
                    logger.debug('Found DER PRIVATE KEY: %s' % keyfile)
                    keydict['type'] = 'privkey'
                    keydict['private'] = True
                    try:
                        pkey_der = subprocess.check_output(
                            ['openssl', 'pkey', '-inform', 'der', '-in', tmpkey, '-pubout', '-outform', 'der',
                             '-passin', 'pass:'], timeout=2, stderr=FNULL)
                        sha256 = hashlib.sha256(pkey_der).hexdigest()
                        keydict['keyhash'] = sha256
                        keydict['protected'] = False
                        logger.debug('%s sha256: %s' % (keyfile, sha256))
                        # sha256 = get_sha256(keyfile, keydata)
                        foundcrt, url = checkcrt(sha256, keytype='pubkey')
                        if foundcrt:
                            logger.debug('%s is listed in crt.sh (PRIVATE KEY)' %
                                         keyfile)
                            keydict['crt'] = url
                    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                        logger.debug('%s Bad pass!' % keyfile)
                        keydict['protected'] = True
                elif 'secp160r1' in asndata:
                    logger.debug('Found DER EC PRIVATE KEY: %s')
                    keydict['type'] = 'privkey-ec'
                    keydict['private'] = True
                elif 'pbeWithSHA1And3-KeyTripleDES-CBC' in asndata or '1.2.410.200004.1.15' in asndata:
                    logger.debug('Found DER PKCS8 PRIVATE KEY: %s' % keyfile)
                    keydict['type'] = 'pkcs8'
                    keydict['private'] = True
                    keydict['protected'] = True
                elif (
                        'rsaEncryption' in asndata or '2.557816.113549.1.1.1' in asndata or 'dsaEncryption' in asndata)\
                        and 'prim: BIT STRING' in asndata:
                    logger.debug('Found DER PUBLIC KEY: %s' % keyfile)
                    keydict['type'] = 'pubkey'
                    keydict['private'] = False
                elif 'id-ecPublicKey' in asndata:
                    logger.debug('Found DER EC PUBLIC KEY: %s' % keyfile)
                    keydict['type'] = 'pubkey-ec'
                    keydict['private'] = False
                elif 'rsaEncryption' in asndata:
                    logger.debug('Found DER RSA public key: %s' % keyfile)
                    keydict['type'] = 'rsa'
                    keydict['private'] = False
                else:
                    logger.debug('Found DER UKNOWN: %s' % keyfile)
                    keydict['type'] = 'UNKNOWN (%s)' % get_magic(keyfile)
                    logger.debug(pformat(asndata))
            else:
                logger.debug('%s is not a DER' % keyfile)

    try:
        os.unlink(tmpkey)
    except FileNotFoundError:
        # Not sure how this can happen, but it apparently can.
        pass
    return keydict


def get_x509_hash(x509text):
    if x509text:
        for line in x509text.splitlines():
            # line = str(line)
            # logger.debug(line)
            if line.startswith('SHA256 Fingerprint='):
                sha256 = line.replace('SHA256 Fingerprint=', '')
                return sha256.replace(':', '').lower()


def decodep12_openssl(keyfile, pw):
    p12dict = {}
    try:
        decoded = subprocess.check_output(
            ['openssl', 'pkcs12', '-in', keyfile, '-info', '-passin', str(r'pass:%s' % pw), '-nodes'], stderr=FNULL,
            timeout=2)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        logger.debug('openssl error!')
        decoded = None

    if decoded:
        logger.debug(decoded)
        x509text = decodex509(decoded)
        sha256 = get_x509_hash(x509text)
        p12dict['certhash'] = sha256
        p12dict['x509text'] = x509text
        # TODO: Is it really private if we only know it's password-protected?
        p12dict['private'] = True
        p12dict['protected'] = True
        p12dict['iskey'] = True
        p12dict['iscert'] = True

    return p12dict


def get_java_keytype(keydata):
    if 'KeyRep' in keydata:
        if keydata.endswith('PUBLIC'):
            return 'public'
        elif keydata.endswith('PRIVATE'):
            return 'private'
    return None


def checkp8pw(keyfile, pw, encoding='pem'):
    cracked = False

    try:
        if encoding == 'pem':
            subprocess.call(
                ['openssl', 'pkcs8', '-in', keyfile, '-passin', str('pass:%s' % pw), ], stderr=FNULL, timeout=2)
            cracked = True
        else:
            subprocess.call(
                ['openssl', 'pkcs8', '-inform', 'der', '-in', keyfile, '-passin', str('pass:%s' % pw), ], stderr=FNULL,
                timeout=2)
            cracked = True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass

    return cracked


def checkp5pw(keyfile, pw, encoding='pem'):
    cracked = False

    try:
        if encoding == 'pem':
            subprocess.call(
                ['openssl', 'pkey', '-in', keyfile, '-passin', str('pass:%s' % pw), ], stderr=FNULL, timeout=2)
            cracked = True
        else:
            subprocess.call(
                ['openssl', 'pkey', '-inform', 'der', '-in', keyfile, '-passin', str('pass:%s' % pw), ], stderr=FNULL,
                timeout=2)
            cracked = True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass

    return cracked


def decodep8_openssl(keyfile, pw, encoding='pem'):
    # logger.debug('*** falling back to openssl! ***')
    p8dict = {}

    try:
        if encoding == 'pem':
            decoded = subprocess.check_output(
                ['openssl', 'pkcs8', '-in', keyfile, '-passin', str('pass:%s' % pw), ], stderr=FNULL, timeout=2)
        else:
            decoded = subprocess.check_output(
                ['openssl', 'pkcs8', '-in', keyfile, '-passin', str('pass:%s' % pw), ], stderr=FNULL, timeout=2)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        decoded = None

    if decoded:
        pass
        # logger.debug('***** decoded: *****')
        # logger.debug(decoded)
        # x509text = decodex509(decoded)
        # sha256 = get_x509_hash(x509text)
        # p12dict['certhash'] = sha256
        # p12dict['x509text'] = x509text
        # p12dict['private'] = True
        # p12dict['protected'] = True
        # p12dict['iskey'] = True
        # p12dict['iscert'] = True

    return p8dict


def p8_is_protected(keyfile, encoding='pem'):
    try:
        if encoding == 'pem':
            decoded = subprocess.check_output(
                ['openssl', 'pkcs8', '-in', keyfile, '-nocrypt', '-nodes'], stderr=FNULL)
        else:
            decoded = subprocess.check_output(
                ['openssl', 'pkcs8', '-in', keyfile, '-passin', '-nocrypt', '-nodes'], stderr=FNULL)
        return False, decoded
    except subprocess.CalledProcessError:
        return True, None


def decodep12_openssl_nokeys(keyfile, pw):
    p12dict = {}
    try:
        decoded = subprocess.check_output(['openssl', 'pkcs12', '-in', keyfile, '-info', '-passin', str(
            'pass:%s' % pw), '-nodes', '-nokeys', '-nomacver'], stderr=FNULL).decode('utf-8', 'backslashreplace')
        if 'CERTIFICATE' in decoded:
            logger.debug('--- Got certificate w/o keys! ---')
            p12dict['x509text'] = decodex509(decoded)
            p12dict['iscert'] = True
    except subprocess.CalledProcessError:
        decoded = None

    if decoded:
        # logger.debug('***** decoded: *****')
        # logger.debug(decoded)
        x509 = decodex509(decoded)

        if x509:
            for line in x509.splitlines():
                # line = str(line)
                # logger.debug(line)
                if line.startswith('SHA256 Fingerprint='):
                    sha256 = str(line).replace('SHA256 Fingerprint=', '').replace(':', '').lower()
                    p12dict['certhash'] = sha256
                    foundcrt, url = checkcrt(sha256)
                    if foundcrt:
                        logger.debug('%s is listed in crt.sh (CERTIFICATE)' % keyfile)
                        p12dict['crt'] = url

    return p12dict


def checkcrt(keyhash, keytype='certificate'):
    # return None, None
    logger.debug('checking crt.sh %s type: %s' % (keyhash, keytype))
    # if type == 'certificate':
    #    return
    match = False
    url = None
    html = None
    if keyhash is not None:
        if not isinstance(keyhash, str):
            type(keyhash)
            logger.debug('%s is %s' % (keyhash, type(keyhash)))
            keyhash = keyhash.decode('utf-8', 'backslashreplace')
        if keytype == 'pubkey':
            url = 'https://crt.sh/?spkisha256=%s' % keyhash
            logger.debug(url)
            try:
                html = urlopen(url)
            except:
                html = None
        else:
            url = 'https://crt.sh/?q=%s' % keyhash
            logger.debug(url)
            try:
                html = urlopen(url)
            except:
                html = None
        if html:
            body = str(html.read())

            if keytype == 'pubkey':
                if 'None found' in body:
                    pass
                elif 'Criteria' in body:
                    logger.debug('Found public key!')
                    match = True
                    # logger.debug(body)
            else:
                if 'Certificate not found' in body:
                    pass
                elif 'Criteria' in body:
                    logger.debug('Found certificate!')
                    match = True
                    # logger.debug(body)
    return match, url


def convertjks(keyfile, pw):
    foundcert = False
    foundkey = False
    reasons = ''

    p12keyfile = keyfile + '.p12'
    if os.path.exists(p12keyfile):
        return p12keyfile

    try:
        subprocess.check_call(['keytool', '-importkeystore', '-srckeystore', keyfile, '-destkeystore',
                               p12keyfile, '-deststoretype', 'pkcs12', '-storepass', pw, '-srcstorepass', pw],
                              stderr=FNULL)
        return p12keyfile

    except subprocess.CalledProcessError:
        logger.debug('Error converting jks file to p12!')


def decodep12(keyfile, pw):
    p12dict = {}
    foundcert = False
    foundkey = False
    url = None
    reasons = ''
    try:
        p12 = crypto.load_pkcs12(open(keyfile, 'rb').read(), pw)
        p12dict['protected'] = True
        logger.debug('pyopenssl loaded crypto OK')
    except crypto.Error:
        logger.info('pyopenssl crypto error! (bad password?)')
        p12 = None

    if p12:
        logger.debug('checking cert and key...')

        if p12.get_certificate():
            logger.debug('p12 certificate in %s' % keyfile)
            p12dict['iscert'] = True
            cert = p12.get_certificate()
            sha256 = cert.digest('sha256').decode('utf-8', 'backslashreplace').replace(':', '').lower()
            logger.debug('certhash: %s' % sha256)
            p12dict['certhash'] = sha256
            p12certificate = crypto.dump_certificate(
                FILETYPE_PEM, p12.get_certificate())
            logger.debug('p12dict-certificate: %s' % p12certificate)
            p12dict['x509text'] = decodex509(p12certificate)
            logger.debug('x509text:\n\n%s' % p12dict['x509text'])
            foundcrt, url = checkcrt(p12dict['certhash'])
            if foundcrt:
                foundcert = True
                p12dict['crt'] = url
                # logger.debug('%s has a CERTIFICATE entry in crt.sh (verify)!!' % keyfile)

        else:
            logger.debug('%s has no certificate! Falling back to openssl...' %
                         keyfile)
            p12dict = decodep12_openssl(keyfile, pw)

        if p12.get_privatekey():
            p12dict['private'] = True
            p12dict['iskey'] = True
            p12privatekey = crypto.dump_privatekey(
                FILETYPE_PEM, p12.get_privatekey())
            kd = get_sha256(keyfile, p12privatekey)
            # logger.debug('kd: %s' % kd)
            p12dict['keyhash'] = kd['keyhash']
            logger.debug('keyhash: %s' % p12dict['keyhash'])
            foundcrt, url = checkcrt(p12dict['keyhash'], keytype='pubkey')
            if foundcrt:
                foundkey = True
                p12dict['crt'] = url
                # logger.debug('%s has a PUBLIC KEY entry in crt.sh!!' % keyfile)
        else:
            p12dict['private'] = False
            logger.debug('%s has no private key!' % keyfile)

        if foundcert or foundkey:
            if foundcert:
                reasons += 'CERTIFICATE '
            if foundkey:
                reasons += 'PRIVATE KEY'
            logger.info('%s is listed in crt.sh (%s)' % (keyfile, reasons))
            p12dict['crt'] = url

    logger.debug(p12dict)
    return p12dict


def decodekeydata(keyfile, keydata):
    encoding = None
    iskey = False
    iscert = False
    asn1 = None
    x509text = None
    keyhash = None
    certhash = None
    keydict = {}
    kd = {}

    logger.debug('Opening %s ...' % keyfile)

    if os.path.getsize(keyfile) > 0:
        # logger.debug('Non-zero file size.  Good.')

        if b'PGP PUBLIC' in keydata:
            logger.debug('Found public PGP key: %s' % keyfile)
            keydict['type'] = 'pgp-public'
            keydict['private'] = False
        elif b'PGP PRIVATE' in keydata:
            logger.debug('Found PRIVATE PGP key: %s' % keyfile)
            keydict['type'] = 'pgp-private'
            keydict['private'] = True
        elif b'BEGIN OpenVPN' in keydata:
            logger.debug('Found OpenVPN key: %s' % keyfile)
            keydict['type'] = 'OpenVPN'
        elif (
                b' RSA PRIVATE KEY' in keydata or b' DSA PRIVATE KEY' in keydata) and b'ENCRYPTED in keydata' and \
                b'BEGIN CERTIFICATE' in keydata:
            logger.debug(
                'Found PEM pkcs5 ENCRYPTED PRIVATE key with CERTIFICATE: %s' % keyfile)
            keydict['private'] = True
            keydict['protected'] = True
            keydict['iskey'] = True
            keydict['iscert'] = True
            keydict['encoding'] = 'pem'
            keydict['type'] = 'pkcs5'
            x509text = decodex509file(keyfile)
            keydict['x509text'] = x509text
            sha256 = get_x509_hash(x509text)
            keydict['certhash'] = sha256
            logger.debug('%s CERT SHA256: %s' % (keyfile, sha256))
            # Check certificate first
            foundcrt, url = checkcrt(sha256)
            if foundcrt:
                logger.debug('%s is listed in crt.sh (CERTIFICATE PRIVATE KEY)' %
                             keyfile)
                keydict['crt'] = url

            # Fall back to public key
            kd = get_sha256(keyfile, keydata)
            sha256 = kd['keyhash']
            logger.debug('%s KEY SHA256: %s' % (keyfile, sha256))
            keydict['keyhash'] = sha256
        elif b'BEGIN ENCRYPTED PRIVATE KEY' in keydata and b'BEGIN CERTIFICATE' in keydata:
            logger.debug(
                'Found PEM pkcs8 ENCRYPTED PRIVATE key with CERTIFICATE: %s' % keyfile)
            keydict['private'] = True
            keydict['protected'] = True
            keydict['iskey'] = True
            keydict['iscert'] = True
            keydict['encoding'] = 'pem'
            keydict['type'] = 'pkcs8'
            x509text = decodex509file(keyfile)
            keydict['x509text'] = x509text
            sha256 = get_x509_hash(x509text)
            keydict['certhash'] = sha256
            logger.debug('%s CERT SHA256: %s' % (keyfile, sha256))
            # Check certificate first
            foundcrt, url = checkcrt(sha256)
            if foundcrt:
                logger.debug('%s is listed in crt.sh (CERTIFICATE PRIVATE KEY)' %
                             keyfile)
                keydict['crt'] = url

            # Fall back to public key
            kd = get_sha256(keyfile, keydata)
            sha256 = kd['keyhash']
            logger.debug('%s KEY SHA256: %s' % (keyfile, sha256))
            keydict['keyhash'] = sha256
        elif (b'BEGIN RSA PRIVATE KEY' in keydata or b'BEGIN DSA PRIVATE KEY' in keydata) and b'ENCRYPTED' in keydata:
            logger.debug('Found PEM pkcs5 ENCRYPTED PRIVATE key: %s' % keyfile)
            keydict['private'] = True
            keydict['iskey'] = True
            keydict['encoding'] = 'pem'
            keydict['protected'] = True
            keydict['type'] = 'pkcs5'
        elif b'BEGIN PRIVATE KEY' in keydata and b'BEGIN CERTIFICATE' in keydata:
            logger.debug('Found PEM pkcs8 PRIVATE key with CERTIFICATE: %s' % keyfile)
            keydict['private'] = True
            keydict['protected'] = False
            keydict['iskey'] = True
            keydict['iscert'] = True
            keydict['encoding'] = 'pem'
            keydict['type'] = 'pkcs8'
            x509text = decodex509file(keyfile)
            sha256 = get_x509_hash(x509text)
            keydict['certhash'] = sha256
            logger.debug('%s SHA256: %s' % (keyfile, sha256))
            keydict['x509text'] = x509text
            kd = get_sha256(keyfile, keydata)
            sha256 = kd['keyhash']
            keydict['keyhash'] = sha256
            foundcrt, url = checkcrt(sha256, keytype='pubkey')
            if foundcrt:
                logger.debug('%s is listed in crt.sh (PRIVATE KEY)' % keyfile)
                keydict['crt'] = url
        elif b'BEGIN ENCRYPTED PRIVATE KEY' in keydata:
            logger.debug('Found PEM PKCS8 private key')
            keydict['private'] = True
            keydict['iskey'] = True
            keydict['encoding'] = 'pem'
            keydict['protected'] = True
            keydict['type'] = 'pkcs8'
        elif (
                b'BEGIN RSA PRIVATE KEY' in keydata or b'BEGIN DSA PRIVATE KEY' in keydata) and b'BEGIN CERTIFICATE' \
                in keydata:
            logger.debug('Found PEM pkcs5 PRIVATE key with CERTIFICATE: %s' % keyfile)
            keydict['private'] = True
            keydict['protected'] = False
            keydict['iskey'] = True
            keydict['iscert'] = True
            keydict['encoding'] = 'pem'
            keydict['type'] = 'pkcs5'
            x509text = decodex509file(keyfile)
            sha256 = get_x509_hash(x509text)
            keydict['certhash'] = sha256
            logger.debug('%s SHA256: %s' % (keyfile, sha256))
            keydict['x509text'] = x509text
            kd = get_sha256(keyfile, keydata)
            sha256 = kd['keyhash']
            keydict['keyhash'] = sha256
            foundcrt, url = checkcrt(sha256, keytype='pubkey')
            if foundcrt:
                logger.debug('%s is listed in crt.sh (PRIVATE KEY)' % keyfile)
                keydict['crt'] = url
        elif b'BEGIN RSA PRIVATE KEY' in keydata or b'BEGIN DSA PRIVATE KEY' in keydata:
            logger.debug('Found PEM pkcs5 PRIVATE key: %s' % keyfile)
            kd = get_sha256(keyfile, keydata)
            # logger.debug('kd: %s' % kd)
            sha256 = kd['keyhash']
            keydict['keyhash'] = sha256
            keydict['private'] = True
            keydict['iskey'] = True
            keydict['encoding'] = 'pem'
            keydict['type'] = 'pkcs5'
            keydict['protected'] = False
            foundcrt, url = checkcrt(sha256, keytype='pubkey')
            if foundcrt:
                logger.debug('%s is listed in crt.sh (PRIVATE KEY)' % keyfile)
                keydict['crt'] = url
        elif b'BEGIN PRIVATE KEY' in keydata:
            logger.debug('Found PEM pkcs5 PRIVATE key: %s' % keyfile)
            kd = get_sha256(keyfile, keydata)
            # logger.debug('kd: %s' % kd)
            sha256 = kd['keyhash']
            keydict['keyhash'] = sha256
            keydict['private'] = True
            keydict['iskey'] = True
            keydict['encoding'] = 'pem'
            keydict['type'] = 'pkcs8'
            keydict['protected'] = False
            foundcrt, url = checkcrt(sha256, keytype='pubkey')
            if foundcrt:
                logger.debug('%s is listed in crt.sh (PRIVATE KEY)' % keyfile)
                keydict['crt'] = url
        elif b'BEGIN RSA PUBLIC KEY' in keydata:
            logger.debug('Found RSA PUBLIC KEY: %s' % keyfile)
            keydict['private'] = False
        elif b'BEGIN EC PUBLIC KEY' in keydata:
            logger.debug('Found EC PUBLIC KEY: %s' % keyfile)
            keydict['private'] = False
        elif b'BEGIN EC PRIVATE KEY' in keydata:
            logger.debug('Found EC PUBLIC KEY: %s' % keyfile)
            keydict['private'] = False
        elif b'BEGIN PUBLIC KEY' in keydata:
            logger.debug('Found PUBLIC KEY: %s' % keyfile)
            keydict['private'] = False
            keydict['type'] = 'pubkey'
        elif b'CERTIFICATE REQUEST' in keydata:
            logger.debug('Found CERTIFICATE REQUEST in %s' % keyfile)
        elif b'BEGIN CERTIFICATE' in keydata:
            logger.debug('Found CERTIFICATE: %s' % keyfile)
            x509text = decodex509(keydata)
            sha256 = get_x509_hash(x509text)
            logger.debug('%s SHA256: %s' % (keyfile, sha256))
            keydict['x509text'] = x509text
            keydict['private'] = False
            keydict['protected'] = False
            keydict['type'] = 'certificate'
        #        elif 'KEY' in keydata:
        #            logger.debug('Found other KEY: %s' % keyfile)it is
        elif b'BEGIN DH PARAMETERS' in keydata:
            logger.debug('Found DH parameters: %s' % keyfile)
            keydict['private'] = False
            keydict['type'] = 'DH'
        elif keydata.startswith(b'LGYK'):
            logger.debug('Found LGYK file: %s' % keyfile)
        else:
            # logger.debug('Checking if base64 encoded...')
            logger.debug('Found unknown key.  base64 encoded?: %s' % keyfile)
            b64encoded, newkeydata = decode_b64(keyfile, keydata)
            if b64encoded:
                logger.debug('base64 encoded data found in %s' % keyfile)
                # recurse into key detection
                keydict = decodekeydata(keyfile, newkeydata)
            else:
                logger.debug('No more base64 decoding to with %s' % keyfile)
                kd = get_sha256(keyfile, keydata, encoding='der')
                # logger.debug('kd: %s' % kd)
                if 'keyhash' in kd:
                    keydict['keyhash'] = kd['keyhash']
                if 'certhash' in kd:
                    keydict['certhash'] = kd['certhash']

        logger.debug('Enumerating properties...')

        if not keydict:
            for prop in kd:
                keydict[prop] = kd[prop]

    return keydict


def decodex509file(keyfile):
    try:
        decoded = subprocess.check_output(
            ['openssl', 'x509', '-in', keyfile, '-text', '-fingerprint', '-sha256']).decode('utf-8', 'backslashreplace')
        return decoded
    except subprocess.CalledProcessError:
        return None


def decodex509(keydata, encoding='pem'):
    decoded = None
    if keydata:
        tmpkey = tempfile.NamedTemporaryFile(suffix='.key').name
        # logger.debug(keydata)
        if isinstance(keydata, str):
            # Don't try to write a string object to a binary file
            try:
                keydata = keydata.encode()
            except UnicodeDecodeError:
                try:
                    keydata = keydata.decode('utf-8').encode('utf-8')
                except:
                    pass
        with open(tmpkey, 'wb') as wp:
            wp.write(keydata)
        if encoding == 'pem':
            try:
                decoded = subprocess.check_output(
                    ['openssl', 'x509', '-in', tmpkey, '-text', '-fingerprint', '-sha256']).decode('utf-8',
                                                                                                   'backslashreplace')
            except subprocess.CalledProcessError:
                pass
            except:
                # Python 2.x isn't so good at Unicode
                pass
        else:
            try:
                decoded = subprocess.check_output(
                    ['openssl', 'x509', '-in', tmpkey, '-inform', 'der', '-text', '-fingerprint', '-sha256']).decode(
                    'utf-8', 'backslashreplace')
            except subprocess.CalledProcessError:
                pass
            except:
                # Python 2.x isn't so good at Unicode
                pass
        os.unlink(tmpkey)
    return decoded


def getsubject(keydata):
    # logger.debug(keydata)
    if keydata:
        keylines = keydata.splitlines()
        for line in keylines:
            if line.startswith('subject='):
                subject = re.sub('^subject=', '', line)
                return subject


def getcn(keydata):
    if keydata:
        subject = getsubject(keydata)
        # logger.debug('subject: %s' % subject)
        splitsubject = subject.split('/CN=')
        if len(splitsubject) > 1:
            cnline = splitsubject[1]
            splitcnline = cnline.split('/')
            cn = splitcnline[0]
            return cn
        else:
            return subject


def extract_keyfile(apkpath, keyfile):
    appname = getappname(apkpath)
    keys_dir = os.path.join('keys', appname)
    keyfile_path = os.path.normpath(os.path.join(keys_dir, keyfile))
    if not os.path.exists(keyfile_path):
        logger.debug('Extracting %s from %s' % (keyfile, apkpath))
        apkfile = zipfile.ZipFile(apkpath)
        apkfile.extract(keyfile, keys_dir)
    else:
        pass

    # clean up mismatched '/' and '\\' directory separators
    keyfile = os.path.normpath(keyfile)
    return os.path.join(keys_dir, keyfile)


def getbkscontents(bksfilepath, password):
    output = None
    logger.debug(['keytool', '-list', '-v', '-keystore', bksfilepath,
                  '-provider', 'org.bouncycastle.jce.provider.BouncyCastleProvider',
                  '-providerpath', 'bcprov-ext.jar', '-storepass', password, '-storetype', 'BKS'])
    try:
        output = subprocess.check_output(['keytool', '-list', '-v', '-keystore', bksfilepath,
                                          '-provider', 'org.bouncycastle.jce.provider.BouncyCastleProvider',
                                          '-providerpath', 'bcprov-ext.jar', '-storepass', password,
                                          '-storetype', 'BKS'], stderr=FNULL)
    except subprocess.CalledProcessError:
        logger.warning('Cannot get BKS contents. Incorrect password?')
    return output


def getfiletype(file):
    filetype = None
    filetype = subprocess.check_output(['file', file, '-b']).strip()
    logger.debug('file reports that %s is of type: "%s"' % (file, filetype))
    return filetype


def getjkscontents(jksfilepath, password):
    output = None
    # logger.debug(['keytool', '-list', '-v', '-keystore', jksfilepath,
    #      '-storepass', password])
    try:
        output = subprocess.check_output(['keytool', '-list', '-v', '-keystore', jksfilepath,
                                          '-storepass', password], stderr=FNULL)
    except subprocess.CalledProcessError:
        pass
    return output


def analyze_jks(keyfile):
    keydict = {}
    logger.debug('Looking at %s...' % keyfile)
    newjks = changejkspassword(keyfile)
    if newjks:
        jkscontents = getjkscontents(newjks, 'password')
        if os.path.exists(newjks):
            os.unlink(newjks)
        if jkscontents:
            try:
                logging.debug(jkscontents.decode('utf-8', 'backslashreplace'))
            except TypeError:
                # Python 2.7
                logging.debug(jkscontents)
            keydict.update(parsekeystorecontents(jkscontents))
            keydict['type'] = 'Java KeyStore'
            logger.debug(keydict)
    return keydict


def analyze_keyfile(keyfile, mimetype=None, passwd=''):
    logger.debug('Analyzing %s with password "%s"...' % (keyfile, passwd))
    keydict = {}
    keydict['keyfile'] = keyfile

    if keyfile.lower().endswith('.ovpn'):
        logger.debug('OpenVPN key!')
        keydict['type'] = 'OpenVPN'

    elif keyfile.lower().endswith('.jks') or keyfile.lower().endswith('.keystore') \
            or mimetype == 'Java KeyStore' or mimetype == 'Java KeyStore':
        # Java Keystore file
        logger.debug('Java Keystore file!')
        keydict.update(analyze_jks(keyfile))
        logger.debug('Got JKS info!')
        keydict['protected'] = True

    elif keyfile.lower().endswith('.bks'):
        # BouncyCastle BKS file
        bksversion = getbksversion(keyfile)
        if passwd:
            bkscontents = getbkscontents(keyfile, passwd)
            keydict.update(parsekeystorecontents(bkscontents))
            logger.debug(keydict)

        keydict['type'] = 'BouncyCastle Keystore V%s' % bksversion
        keydict['protected'] = True

    elif keyfile.lower().endswith('.pfx') or keyfile.lower().endswith('.p12'):
        logger.debug('Analyzing pkcs12 file (due to extension)...')
        # PKCS12 file
        if validasn(keyfile):

            if passwd:
                keydict.update(decodep12(keyfile, passwd))
                keydict['type'] = 'pkcs12'
                # logger.debug('--- \n %s' % keydict)
            else:
                # Try to get certificate details w/o password as a last resort
                logger.debug('Attempting openssl extraction without keys...')
                keydict.update(decodep12_openssl_nokeys(keyfile, ''))
                if 'x509text' not in keydict:
                    keydict['type'] = 'pkcs12'
                    keydict['protected'] = True
                    keydict['protected'] = True

            logger.debug('p12 keydict: %s' % logger.debug(pformat(keydict)))
        else:
            # No valid ASN, so probably not really a PKCS#12 file
            # keydict['type'] = 'INVALID'
            pass
        
    else:
        # Non-PKCS12 or JKS file (pkcs8, pkcs5)
        logger.debug('Selecting %s' % keyfile)
        try:
            with open(keyfile, 'rb') as kp:
                keydata = kp.read()
        except:
            return
        keydict.update(decodekeydata(keyfile, keydata))

        if 'type' in keydict:
            if keydict['type'] == 'pkcs8':
                if passwd:
                    logger.debug('Trying manual password (%s)...' % passwd)
                    found = checkp8pw(keyfile, passwd, encoding=keydict['encoding'])
                    if found:
                        keydict['password'] = passwd

                # regardless of how password is derived for the pkcs8 file, get the hash of it
                logger.debug('* Getting sha256 of %s ...' % keyfile)
                sha256 = get_keyhash(keyfile, encoding=keydict['encoding'], pw=passwd)
                if sha256:
                    keydict['keyhash'] = sha256
                    foundcrt, url = checkcrt(sha256, keytype='pubkey')
                    if foundcrt:
                        logger.info('%s is listed in crt.sh (PRIVATE KEY)' %
                                    keyfile)
                        keydict['crt'] = url
            elif keydict['type'] == 'pkcs5' and keydict['private'] == 1:
                # regardless of how password is derived for the pkcs5 file, get the hash of it
                logger.debug('* Getting sha256 of %s ...' % keyfile)
                sha256 = get_keyhash(keyfile, encoding=keydict['encoding'], pw=passwd)
                if sha256:
                    keydict['keyhash'] = sha256
                    foundcrt, url = checkcrt(sha256, keytype='pubkey')
                    if foundcrt:
                        logger.info('%s is listed in crt.sh (PRIVATE KEY)' %
                                    keyfile)
                        keydict['crt'] = url
        else:
            # Uknown key type
            keydict['type'] = 'UNKNOWN (%s)' % get_magic(keyfile)
    logger.debug('keydict: %s' % pformat(keydict))
    return keydict


def print_key(keydict):
    if keydict:
        important = False
        if 'type' in keydict:
            if 'private' in keydict:
                if keydict['private']:
                    important = True
            if 'protected' in keydict:
                if keydict['protected']:  # and keydict['type'] != 'Java KeyStore':
                    # We can tell the contents of JKS files, so no need to mention protected keystores
                    # without private keys
                    important = True

            # Private or protected key file
            for keyprop in keydict:
                if keyprop != 'x509text' and keyprop != 'asn1' and keyprop != 'keystoretext':
                    if important:
                        logger.warning('%s: %s' % (keyprop, keydict[keyprop]))
                    else:
                        logger.info('%s: %s' % (keyprop, keydict[keyprop]))
                else:
                    logger.info('%s: %s%s' % (keyprop, os.linesep, keydict[keyprop]))

                    # if important:
                    #     # Only print details in verbose mode or higher
                    #     logger.warning('%s: %s%s' % (keyprop, os.linesep, keydict[keyprop]))
                    # else:
                    #     # Only print details in verbose mode or higher
                    #     logger.info('%s: %s%s' % (keyprop, os.linesep, keydict[keyprop]))
            
            if important:
                logger.warning('%s=====================%s' % (os.linesep, os.linesep))
            else:
                logger.info('%s=====================%s' % (os.linesep, os.linesep))


def print_results(keydict):
    if 'type' in keydict:
        attriblist = []
        if 'private' in keydict:
            if keydict['private']:
                attriblist.append('private')
        if 'protected' in keydict:
            if keydict['protected']:
                attriblist.append('protected')
        if attriblist:
            attribstring = ','.join(attriblist)
            logger.warning('%s includes %s key:  %s (%s)' % (keydict['apkpath'], attribstring, keydict['keyfile'],
                                                             keydict['type']))
        logger.info('%s: %s' % (keydict['keyfile'], keydict['type']))
        for keyprop in keydict:
            if keyprop != 'keyfile':
                if keyprop == 'crt':
                    logger.warning(
                        '%s key %s is listed in crt.sh: %s' % (keydict['apkpath'], keydict['keyfile'], keydict['crt']))
                elif keyprop != 'x509text' and keyprop != 'asn1':
                    logger.info('%s: %s' % (keyprop, keydict[keyprop]))
                else:
                    # add extra linefeed before lengthy properties
                    logger.info('%s: %s%s' % (keyprop, os.linesep, keydict[keyprop]))
        logger.info('')


def changejkspwandparse(keyfile):
    appname = getappname(keyfile)
    newjks = changejkspassword(keyfile)
    if newjks:
        jkscontents = getjkscontents(newjks, 'password')
        if jkscontents:
            keydict = parsekeystorecontents(jkscontents)
            logger.debug(keydict)


def getappname(apkpath):
    apkfile = os.path.basename(apkpath)
    appname = re.sub('\.apk$', '', apkfile)
    return appname


def getdirname(apkpath):
    return os.path.dirname(apkpath)


def extract_apk(apkpath):
    apkpath = os.path.normpath(apkpath)
    logger.debug('Extracting APK: %s' % apkpath)
    appname = getappname(apkpath)
    extract_dir = os.path.join('extracted', getappname(apkpath))
    if not os.path.exists(extract_dir):
        logger.debug('"%s" does not exist!  Extracting...' % extract_dir)
        tmppath = os.path.join(tempfile.gettempdir(), appname)
        if not os.path.exists(tmppath):
            os.mkdir(tmppath)
        logger.debug('Extracting %s' % getappname(apkpath))
        os.mkdir(extract_dir)
        try:
            subprocess.call(['apktool', 'd', apkpath, '-p', tmppath, '-o', extract_dir, '-f'])
        except FileNotFoundError:
            try:
                # On Windows, apktool lives as the apktool.bat wrapper
                subprocess.call(['apktool.bat', 'd', apkpath, '-p', tmppath, '-o', extract_dir, '-f'])
            except subprocess.CalledProcessError:
                logger.debug('******** %s failed to extract!' % appname)
        except subprocess.CalledProcessError:
            logger.debug('******** %s failed to extract!' % appname)
        shutil.rmtree(tmppath)


def find_keyfiles(filedict):
    keyfiles = []
    for filename in filedict:
        if possible_key(filename, filedict[filename]):
            logger.debug('%s (%s) is possibly a private key!' % (filename, filedict[filename]))
            keyfiles.append(filename)
    return keyfiles


def possible_key(filename, filetype):
    if not filetype:
        try:
            filetype = get_magic(filename)
        except:
            pass
    if not filetype:
        # Unable to use filemagic to determine file type
        filetype = 'UNKNOWN'
    filename = filename.lower()
    filetype = filetype.lower()
    ignorefilenames = ['assets.split', 'bouncycastle', 'resource.split', 'npm/parse-asn1', 'googleapis/google.jks',
                       'examples/echoserver/ssl/bogus.cert']
    ignorefiletypes = ['011Secret', 'JPEG', 'public']
    for filenamepattern in ignorefilenames:
        if filenamepattern in filename:
            return False
    for filetypepattern in ignorefiletypes:
        if filetypepattern in filetype:
            return False
    if filename.endswith('.key') or filename.endswith('.pem') or filename.endswith('.der') \
            or filename.endswith('.p12') or filename.endswith('.bks') or filename.endswith('.jks') \
            or filename.endswith('.pfx') or filename.endswith('.keystore') or filename.endswith('.cer') or 'key' in \
            filetype:
        return True


def get_apk_signer(apkpath):
    sha256 = None
    jsonpath = re.sub('\.apk$', '.apkinfo.json', apkpath)
    logger.debug('Looking at %s' % jsonpath)
    if os.path.exists(jsonpath):
        aidict = {}
        with open(jsonpath) as jf:
            try:
                aidict = json.load(jf)
            except:
                return
        if 'certs' in aidict:
            try:
                sha256 = aidict['certs'][0]['sha256']
            except IndexError:
                pass
            return sha256


def scan_dir(keydir, keytest, check_keyused=False):
    lastroot = None
    roots_scanned = 0
    for root, dirs, files in os.walk(keydir, followlinks=False):
        if roots_scanned > 20:
            gc.collect()
            roots_scanned = 0
        if lastroot != root:
            lastroot = root
            roots_scanned += 1
        if files:
            for name in files:
                testfile = os.path.join(root, name)
                if keytest == 'apk':
                    check_apk(testfile, check_keyused)
                elif keytest == 'key':
                    check_keyfile(testfile)


def check_keyfile(keypath):
    logger.debug('Checking key %s' % keypath)
    if os.path.exists(keypath):
        if os.path.isdir(os.path.realpath(keypath)):
            scan_dir(keypath, 'key')
        else:
            if possible_key(keypath, None):
                keyfiletype = get_magic(keypath)
                keydict = analyze_keyfile(keypath, keyfiletype)
                print_key(keydict)


def check_apk(apkpath, check_keyused=False, passwd=None):
    global logger
    keydict = {}

    if os.path.exists(apkpath):
        if os.path.isdir(apkpath):
            scan_dir(apkpath, 'apk', check_keyused)
        else:
            if apkpath.endswith('.apk'):
                logger.info('%s: %s' % ('Analyzing APK', apkpath))
                if not androapkinfo.getapkinfo(apkpath):
                    return
                apksigner = get_apk_signer(apkpath)
                logger.debug('APK signing key SHA256: %s' % apksigner)
                filedict = {}
                aidict = get_apk_files(apkpath)
                if 'files' in aidict:
                    for filelist in aidict['files']:
                        filedict[filelist[0]] = filelist[1]
                    keyfiles = find_keyfiles(filedict)
                    for keyfile in keyfiles:
                        keypath = extract_keyfile(apkpath, keyfile)
                        keydict = analyze_keyfile(keypath, filedict[keyfile], passwd=passwd)
                        if check_keyused:
                            logging.debug('Checking if %s is used by %s...' % (keyfile, apkpath))
                            keydict['key used'] = key_used(apkpath, keyfile)
                        keydict['apkpath'] = apkpath
                        keydict['keyfile'] = keyfile
                        keydict['keypath'] = keypath
                        if 'keyhash' in keydict:
                            logger.debug('keyhash: %s' % keydict['keyhash'])
                            if apksigner == keydict['keyhash']:
                                logger.warning('%s distributes its signing key as: %s' % (apkpath, keyfile))
                                keydict['APK signing key'] = True
                        elif 'certhash' in keydict and 'private' in keydict:
                            if keydict['private']:
                                logger.debug('certhash: %s' % keydict['certhash'])
                                if apksigner == keydict['certhash']:
                                    logger.warning('%s distributes its signing key as: %s' % (apkpath, keyfile))
                                    keydict['APK signing key'] = True
                        print_results(keydict)
                else:
                    logger.debug('No files found in %s ?!' % apkpath)
    else:
        logger.warning('%s not found!' % apkpath)


def get_apk_files(apkpath):
    aidict = {}
    jsonpath = re.sub('\.apk$', '.apkinfo.json', apkpath)
    logger.debug('Loading JSON data file %s' % jsonpath)
    if os.path.exists(jsonpath):
        with open(jsonpath) as jf:
            try:
                aidict = json.load(jf)
            except json.decoder.JSONDecodeError:
                logger.debug('JSON decoding error! Deleting %s ...' % jsonpath)
                os.unlink(jsonpath)
                pass
    else:
        pass
        # Extract androapkinfo stuff here
    return aidict


def key_used(apkpath, keyfile):
    keyused = False
    logger.debug('Checking if %s is used' % keyfile)
    appname = getappname(os.path.basename(apkpath))
    logger.debug('appname: %s' % appname)
    extract_dir = os.path.join('extracted', appname)
    keyname = os.path.basename(keyfile)
    # A keyfile often has a reference to its own name.  We'll exclude that
    # below
    extracted_keypath = re.sub('^keys/', 'extracted/', keyfile)
    logger.debug('about to extract %s for %s' % (apkpath, appname))
    extract_apk(apkpath)
    logger.debug('Checking %s for %s...' % (extract_dir, keyname))
    # parsed = subprocess.check_output('grep -F -r -l %s %s/' % (keyname, extract_dir), shell=True)
    try:
        parsed = subprocess.check_output(
            ['grep', '-F', '-r', '-l', '--', keyname, extract_dir])
    except subprocess.CalledProcessError:
        logger.debug('Key is not used!')
        return keyused
    # logger.debug(parsed)
    for line in parsed.splitlines():
        line = line.rstrip().decode('utf-8', 'backslashreplace')
        if not ignoreline(extracted_keypath, line):
            filematch = re.sub('^Binary file ', '', line)
            filematch = re.sub(' matches$', '', filematch)
            try:
                logger.warning('%s is referenced by %s' % (keyfile, filematch))
            except:
                # Don't choke on unicode strings.  Above only works on ASCII in
                # python2
                pass
            keyused = True
    logger.debug('Key used: %s' % keyused)
    return keyused


def ignoreline(extracted_keypath, line):
    if '/META-INF/' in line or '/apktool.yml' in line or '/strings.txt' in line or line.endswith(extracted_keypath):
        return True
    else:
        return False


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        'A tool for analyzing key files, with Android APK support')
    parser.add_argument('-e', '--extract', action='store',
                        dest='extract_apk', help='Extract specified APK using apktool')
    parser.add_argument('-u', '--checkused', action='store_true',
                        dest='check_keyused', help='Check if the key file is referenced by the app (slow)')
    parser.add_argument('-k', '--key', action='store',
                        dest='check_keyfile', help='Key file or directory')
    parser.add_argument('-p', '--password', action='store',
                        dest='password', help='Specify password')
    parser.add_argument('-v', '--verbose', action='store_true',
                        dest='verbose', help='Verbose output')
    parser.add_argument('-d', '--debug', action='store_true',
                        dest='debug', help='Debug output')
    parser.add_argument('apkpath', type=str, nargs='?', help='APK file or directory')

    if len(sys.argv) < 2:
        sys.argv.append("-h")
    args = parser.parse_args()

    if args.debug:
        loglevel = logging.DEBUG
    elif args.verbose:
        loglevel = logging.INFO
    else:
        loglevel = logging.WARNING

    logging.basicConfig(format='%(message)s', level=loglevel)

    if args.extract_apk:
        extract_apk(args.extract_apk)
    elif args.check_keyfile:
        check_keyfile(args.check_keyfile)
    elif args.apkpath:
        check_apk(args.apkpath, check_keyused=args.check_keyused, passwd=args.password)
