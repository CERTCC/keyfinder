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

import os
import json
import binascii
import re

try:
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print('cryptography library not found. Key processing capabilities will be limited.')

try:
    from androguard.core import androconf
except ImportError:
    print('Androguard library not found. APK parsing abilities will not be available.')


apkinfo = {}


# noinspection PyProtectedMember,PyProtectedMember,PyProtectedMember
def get_Name(name, short=False):
    """
        Return the distinguished name of an X509 Certificate
        :param name: Name object to return the DN from
        :param short: Use short form (Default: False)
        :type name: :class:`cryptography.x509.Name`
        :type short: Boolean
        :rtype: str
    """

    # For the shortform, we have a lookup table
    # See RFC4514 for more details
    sf = {
        "countryName": "C",
        "stateOrProvinceName": "ST",
        "localityName": "L",
        "organizationalUnitName": "OU",
        "organizationName": "O",
        "commonName": "CN",
        "emailAddress": "E",
    }
    return ", ".join(
        ["{}={}".format(attr.oid._name if not short or attr.oid._name not in sf else sf[attr.oid._name], attr.value) for
         attr in name])


def get_Certificate(cert, short=False):
    """
        Print Fingerprints, Issuer and Subject of an X509 Certificate.
        :param cert: X509 Certificate to print
        :param short: Print in shortform for DN (Default: False)
        :type cert: :class:`cryptography.x509.Certificate`
        :type short: Boolean
    """
    certdict = {}

    try:
        # Older androguard uses python cryptography library
        for h in [hashes.MD5, hashes.SHA1, hashes.SHA256, hashes.SHA512]:
            certdict[h.name] = binascii.hexlify(
                cert.fingerprint(h())).decode("ascii")
        certdict['issuer'] = get_Name(cert.issuer, short=short)
        certdict['subject'] = get_Name(cert.subject, short=short)
    except AttributeError:
        # Newer androguard uses pyasn1, which requires different syntax/functions
        certdict['sha1'] = cert.sha1_fingerprint.replace(' ', '').lower()
        certdict['sha256'] = cert.sha256_fingerprint.replace(' ', '').lower()
        # certdict['issuer'] = get_certificate_name_string(cert.issuer, short=short)
        certdict['issuer'] = cert.issuer.human_friendly
        # certdict['subject'] = get_certificate_name_string(cert.subject, short=short)
        certdict['subject'] = cert.subject.human_friendly

    return certdict


def extract_dvm_info(apk, apkfile):
    # See
    # https://github.com/androguard/androguard/blob/master/androguard/core/bytecodes/apk.py
    providerlist = []
    apkinfo['files'] = tuple(i for i in apk.get_files_information())
    apkinfo['declared_permissions'] = tuple(
        i for i in apk.get_declared_permissions_details())
    apkinfo['requested_permissions'] = tuple(i for i in apk.get_permissions())
    try:
        apkinfo['main_activity'] = apk.get_main_activity()
        actdict = {}
        for activity in apk.get_activities():
            if not isinstance(activity, str):
                # Don't allow binary activities.  Decode to unicode
                activity = activity.decode()
            actdict[activity] = apk.get_intent_filters('activity', activity)
        apkinfo['activities'] = actdict
        servicedict = {}
        for service in apk.get_services():
            servicedict[service] = apk.get_intent_filters('service', service)
        receiverdict = {}
        for receiver in apk.get_receivers():
            receiverdict[receiver] = apk.get_intent_filters('receiver', receiver)
        for provider in apk.get_providers():
            if not isinstance(provider, str):
                providerlist.append(provider.decode())
            else:
                providerlist.append(provider)
        apkinfo['providers'] = providerlist
    except:
        pass
    certlist = []
    for certname in apk.get_signature_names():
        certlist.append(get_Certificate(apk.get_certificate(certname)))
    apkinfo['certs'] = certlist

    jsonfile = re.sub('\.apk$', '.apkinfo.json', apkfile)
    with open(jsonfile, 'w') as of:
        json.dump(apkinfo, of, indent=2)


def getapkinfo(apkfile):
    goodapk = False
    if apkfile is not None:

        ret_type = androconf.is_android(apkfile)

        apkinfo['filename'] = apkfile
        if ret_type == "APK":
            jsonfile = re.sub('\.apk$', '.apkinfo.json', apkfile)
            if not os.path.exists(jsonfile):
                # print('Analyzing APK: %s ...' % apkfile)
                from androguard.core.bytecodes import apk
                try:
                    a = apk.APK(apkfile)
                    if a.is_valid_APK():
                        extract_dvm_info(a, apkfile)
                        goodapk = True
                    else:
                        print("%s - INVALID" % apkfile)
                        return False
                except Exception as e:
                    print("%s ERROR" % apkfile, e)
                    import traceback
                    traceback.print_exc()
            else:
                goodapk = True
        else:
            pass

    return goodapk



