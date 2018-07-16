* [Overview](#overview)
* [Installation](#installation)
* [Keyfinder Usage](#keyfinder-usage)
   * [Key Parsing](#key-parsing)
      * [Simple Example](#simple-example)
      * [Verbose Output](#verbose-output)
   * [APK Parsing](#apk-parsing)
      * [Simple APK Example](#simple-apk-example)
      * [crt.sh Checking](#crtsh-checking)
      * [Key File Usage](#key-file-usage)

# Overview
CERT Keyfinder is a utility for finding and analyzing key files on a filesystem as well as contained within Android APK files.  CERT Keyfinder development was sponsored by the United States Department of Homeland Security (DHS).  Installation requirements:

1. Python (3.x recommended)
    * androguard
    * python-magic
    * PyOpenSSL
1. apktool
1. grep
1. OpenSSL
1. Java

# Installation
1. Obtain the Keyfinder code.  This can be accomplished by performing a `git clone` of the Keyfinder repository, or by downloading a zip file of the repository.
1. Install Python dependencies:
`$ pip3 install androguard python-magic PyOpenSSL`
On Windows platforms, use the `python-magic-bin` package instead of `python-magic`. This will provide the DLL required to analyze file magic. 

# Keyfinder Usage

```
$ python3 keyfinder.py
usage: A tool for analyzing key files, with Android APK support
       [-h] [-e EXTRACT_APK] [-u] [-k CHECK_KEYFILE] [-p PASSWORD] [-v] [-d]
       [apkpath]

positional arguments:
  apkpath               APK file or directory

optional arguments:
  -h, --help            show this help message and exit
  -e EXTRACT_APK, --extract EXTRACT_APK
                        Extract specified APK using apktool
  -u, --checkused       Check if the key file is referenced by the app (slow)
  -k CHECK_KEYFILE, --key CHECK_KEYFILE
                        Key file or directory
  -p PASSWORD, --password PASSWORD
                        Specify password
  -v, --verbose         Verbose output
  -d, --debug           Debug output

```

## Key Parsing

CERT Keyfinder can be used to scan the files on your system, reporting only private and/or password-protected key files by default.  

### Simple Example
For example, running Keyfinder on the `~` directory on a CERT Tapioca system:
```
$ python keyfinder.py -k ~/tapioca
keyfile: /home/tapioca/tapioca/.mitmproxy/mitmproxy-ca-cert.p12
type: pkcs12
protected: True

=====================

keyfile: /home/tapioca/tapioca/.mitmproxy/mitmproxy-ca.pem
private: True
protected: False
iskey: True
iscert: True
encoding: pem
type: pkcs8
certhash: 902073e933d0bf9b3da49a3a120d0adecdf031960f87576947bdc3157cd62d8e
keyhash: 3aae8d85450bae20aaf360d046bc0d90b2998800b3a7356f0742ef6a8824e423

=====================
```
The above command line will look at every file in the specified directory, determine if it is a possible key file by using the file extension and file magic, and finally it will display brief details for any file that is determined to be a private and/or password-protected key file.  

### Verbose Output
If we wish to get more details, we can run the same command line, but with the verbose `-v` flag:

```
$ python keyfinder.py -k ~/tapioca -v
keyfile: /home/tapioca/tapioca/.mitmproxy/mitmproxy-ca-cert.cer
x509text: 
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 15259797775478 (0xde0f2d36476)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=mitmproxy, O=mitmproxy
        Validity
            Not Before: May  8 19:16:17 2018 GMT
            Not After : May  9 19:16:17 2021 GMT
        Subject: CN=mitmproxy, O=mitmproxy
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:b0:91:be:f6:cc:62:5f:fd:af:9e:48:1e:b9:c5:
                    59:ca:36:f0:02:a7:e5:62:48:5c:26:1b:78:c1:3a:
                    74:02:0f:af:85:74:0c:d7:24:5f:85:4c:ce:e0:9b:
                    2f:3f:0a:85:ba:8f:36:3e:bc:4b:3b:3c:13:d8:8f:
                    b9:46:38:42:69:9c:b2:7e:51:fa:cc:ab:fc:57:95:
                    49:89:45:5c:a2:17:b9:6c:fc:a3:f6:0c:df:50:9e:
                    36:28:71:1e:43:d2:e7:13:0a:ec:25:e1:5d:27:a5:
                    69:5d:48:75:f2:4c:44:3f:b6:cd:33:a2:db:49:d3:
                    97:4d:4f:2c:60:ac:a0:4f:4a:96:19:52:d9:4d:b9:
                    ce:70:49:e6:2d:eb:99:c6:cb:45:8c:5b:df:79:0a:
                    10:53:44:ac:c2:a3:6c:fd:7d:a3:04:93:73:5e:2e:
                    d2:d9:b9:c9:f2:5d:ad:a0:68:6e:b9:43:31:2e:2b:
                    31:b5:8d:2b:09:04:7b:63:1e:79:5a:0b:cc:02:16:
                    7e:6c:7e:0b:04:d0:07:d6:3b:f9:6d:f8:80:e4:b5:
                    e2:36:73:ee:c2:6a:a2:b3:ad:20:ac:42:00:24:61:
                    ad:ff:ed:8d:3d:e7:9f:36:ed:51:a1:91:cf:13:60:
                    b4:40:1c:e4:82:29:4e:d5:05:43:36:2d:04:b2:37:
                    c5:cb
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            Netscape Cert Type: 
                SSL CA
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication, E-mail Protection, Time Stamping, Microsoft Individual Code Signing, Microsoft Commercial Code Signing, Microsoft Trust List Signing, Microsoft Server Gated Crypto, Microsoft Encrypted File System, Netscape Server Gated Crypto
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Subject Key Identifier: 
                18:85:41:4C:5B:CD:3F:32:0B:BE:12:F2:C8:6E:98:78:6E:B6:EA:33
    Signature Algorithm: sha256WithRSAEncryption
         9a:84:35:8c:50:81:ae:53:46:cd:25:31:24:22:3a:25:a3:b0:
         c9:bd:68:d9:7f:06:3c:88:cd:23:0e:24:00:06:55:c6:91:0f:
         81:a9:b6:1d:3d:01:58:54:8b:bc:e6:38:f3:0b:1d:fb:6c:d8:
         67:46:d4:0e:cc:5c:ff:17:a4:e6:d0:95:e7:8c:c3:95:4c:80:
         40:51:5b:b7:32:65:2d:50:25:26:0b:4a:d4:9d:35:59:f0:d9:
         cc:1e:2b:54:47:24:02:64:6d:f3:01:85:02:c8:4e:7d:02:13:
         30:0c:92:c8:7c:48:2a:c6:dd:64:54:5f:8e:65:ce:c6:91:27:
         61:e9:c6:51:25:f2:f4:f7:33:7e:48:c5:0e:a1:c1:86:83:6a:
         5a:84:b7:3d:73:28:0b:0c:5a:98:eb:64:1f:a8:72:fd:ca:71:
         3c:e7:37:b4:ff:94:ce:15:3d:d5:f4:e0:18:75:41:3c:f9:63:
         01:6e:de:73:73:1e:bf:e2:02:d7:47:a6:4a:9e:70:2d:ce:06:
         c4:a9:e5:a5:3b:b9:5f:d8:b6:9d:33:58:fc:38:ce:fb:80:0b:
         ad:5d:6f:56:62:ca:81:d1:27:36:5e:6f:03:7b:2b:75:29:bd:
         85:d3:cd:11:a3:32:b7:72:09:d2:87:10:cd:fd:4b:bb:88:28:
         ce:15:3e:d2
SHA256 Fingerprint=90:20:73:E9:33:D0:BF:9B:3D:A4:9A:3A:12:0D:0A:DE:CD:F0:31:96:0F:87:57:69:47:BD:C3:15:7C:D6:2D:8E
-----BEGIN CERTIFICATE-----
MIIDoTCCAomgAwIBAgIGDeDy02R2MA0GCSqGSIb3DQEBCwUAMCgxEjAQBgNVBAMM
CW1pdG1wcm94eTESMBAGA1UECgwJbWl0bXByb3h5MB4XDTE4MDUwODE5MTYxN1oX
DTIxMDUwOTE5MTYxN1owKDESMBAGA1UEAwwJbWl0bXByb3h5MRIwEAYDVQQKDAlt
aXRtcHJveHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCwkb72zGJf
/a+eSB65xVnKNvACp+ViSFwmG3jBOnQCD6+FdAzXJF+FTM7gmy8/CoW6jzY+vEs7
PBPYj7lGOEJpnLJ+UfrMq/xXlUmJRVyiF7ls/KP2DN9QnjYocR5D0ucTCuwl4V0n
pWldSHXyTEQ/ts0zottJ05dNTyxgrKBPSpYZUtlNuc5wSeYt65nGy0WMW995ChBT
RKzCo2z9faMEk3NeLtLZucnyXa2gaG65QzEuKzG1jSsJBHtjHnlaC8wCFn5sfgsE
0AfWO/lt+IDkteI2c+7CaqKzrSCsQgAkYa3/7Y0955827VGhkc8TYLRAHOSCKU7V
BUM2LQSyN8XLAgMBAAGjgdAwgc0wDwYDVR0TAQH/BAUwAwEB/zARBglghkgBhvhC
AQEEBAMCAgQweAYDVR0lBHEwbwYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcD
BAYIKwYBBQUHAwgGCisGAQQBgjcCARUGCisGAQQBgjcCARYGCisGAQQBgjcKAwEG
CisGAQQBgjcKAwMGCisGAQQBgjcKAwQGCWCGSAGG+EIEATAOBgNVHQ8BAf8EBAMC
AQYwHQYDVR0OBBYEFBiFQUxbzT8yC74S8shumHhutuozMA0GCSqGSIb3DQEBCwUA
A4IBAQCahDWMUIGuU0bNJTEkIjolo7DJvWjZfwY8iM0jDiQABlXGkQ+BqbYdPQFY
VIu85jjzCx37bNhnRtQOzFz/F6Tm0JXnjMOVTIBAUVu3MmUtUCUmC0rUnTVZ8NnM
HitURyQCZG3zAYUCyE59AhMwDJLIfEgqxt1kVF+OZc7GkSdh6cZRJfL09zN+SMUO
ocGGg2pahLc9cygLDFqY62QfqHL9ynE85ze0/5TOFT3V9OAYdUE8+WMBbt5zcx6/
4gLXR6ZKnnAtzgbEqeWlO7lf2LadM1j8OM77gAutXW9WYsqB0Sc2Xm8Deyt1Kb2F
080RozK3cgnShxDN/Uu7iCjOFT7S
-----END CERTIFICATE-----

private: False
protected: False
type: certificate

=====================

keyfile: /home/tapioca/tapioca/.mitmproxy/mitmproxy-dhparam.pem
private: False
type: DH

=====================

keyfile: /home/tapioca/tapioca/.mitmproxy/mitmproxy-ca-cert.p12
type: pkcs12
protected: True

=====================

keyfile: /home/tapioca/tapioca/.mitmproxy/mitmproxy-ca.pem
private: True
protected: False
iskey: True
iscert: True
encoding: pem
type: pkcs8
certhash: 902073e933d0bf9b3da49a3a120d0adecdf031960f87576947bdc3157cd62d8e
x509text: 
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 15259797775478 (0xde0f2d36476)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=mitmproxy, O=mitmproxy
        Validity
            Not Before: May  8 19:16:17 2018 GMT
            Not After : May  9 19:16:17 2021 GMT
        Subject: CN=mitmproxy, O=mitmproxy
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:b0:91:be:f6:cc:62:5f:fd:af:9e:48:1e:b9:c5:
                    59:ca:36:f0:02:a7:e5:62:48:5c:26:1b:78:c1:3a:
                    74:02:0f:af:85:74:0c:d7:24:5f:85:4c:ce:e0:9b:
                    2f:3f:0a:85:ba:8f:36:3e:bc:4b:3b:3c:13:d8:8f:
                    b9:46:38:42:69:9c:b2:7e:51:fa:cc:ab:fc:57:95:
                    49:89:45:5c:a2:17:b9:6c:fc:a3:f6:0c:df:50:9e:
                    36:28:71:1e:43:d2:e7:13:0a:ec:25:e1:5d:27:a5:
                    69:5d:48:75:f2:4c:44:3f:b6:cd:33:a2:db:49:d3:
                    97:4d:4f:2c:60:ac:a0:4f:4a:96:19:52:d9:4d:b9:
                    ce:70:49:e6:2d:eb:99:c6:cb:45:8c:5b:df:79:0a:
                    10:53:44:ac:c2:a3:6c:fd:7d:a3:04:93:73:5e:2e:
                    d2:d9:b9:c9:f2:5d:ad:a0:68:6e:b9:43:31:2e:2b:
                    31:b5:8d:2b:09:04:7b:63:1e:79:5a:0b:cc:02:16:
                    7e:6c:7e:0b:04:d0:07:d6:3b:f9:6d:f8:80:e4:b5:
                    e2:36:73:ee:c2:6a:a2:b3:ad:20:ac:42:00:24:61:
                    ad:ff:ed:8d:3d:e7:9f:36:ed:51:a1:91:cf:13:60:
                    b4:40:1c:e4:82:29:4e:d5:05:43:36:2d:04:b2:37:
                    c5:cb
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            Netscape Cert Type: 
                SSL CA
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication, E-mail Protection, Time Stamping, Microsoft Individual Code Signing, Microsoft Commercial Code Signing, Microsoft Trust List Signing, Microsoft Server Gated Crypto, Microsoft Encrypted File System, Netscape Server Gated Crypto
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Subject Key Identifier: 
                18:85:41:4C:5B:CD:3F:32:0B:BE:12:F2:C8:6E:98:78:6E:B6:EA:33
    Signature Algorithm: sha256WithRSAEncryption
         9a:84:35:8c:50:81:ae:53:46:cd:25:31:24:22:3a:25:a3:b0:
         c9:bd:68:d9:7f:06:3c:88:cd:23:0e:24:00:06:55:c6:91:0f:
         81:a9:b6:1d:3d:01:58:54:8b:bc:e6:38:f3:0b:1d:fb:6c:d8:
         67:46:d4:0e:cc:5c:ff:17:a4:e6:d0:95:e7:8c:c3:95:4c:80:
         40:51:5b:b7:32:65:2d:50:25:26:0b:4a:d4:9d:35:59:f0:d9:
         cc:1e:2b:54:47:24:02:64:6d:f3:01:85:02:c8:4e:7d:02:13:
         30:0c:92:c8:7c:48:2a:c6:dd:64:54:5f:8e:65:ce:c6:91:27:
         61:e9:c6:51:25:f2:f4:f7:33:7e:48:c5:0e:a1:c1:86:83:6a:
         5a:84:b7:3d:73:28:0b:0c:5a:98:eb:64:1f:a8:72:fd:ca:71:
         3c:e7:37:b4:ff:94:ce:15:3d:d5:f4:e0:18:75:41:3c:f9:63:
         01:6e:de:73:73:1e:bf:e2:02:d7:47:a6:4a:9e:70:2d:ce:06:
         c4:a9:e5:a5:3b:b9:5f:d8:b6:9d:33:58:fc:38:ce:fb:80:0b:
         ad:5d:6f:56:62:ca:81:d1:27:36:5e:6f:03:7b:2b:75:29:bd:
         85:d3:cd:11:a3:32:b7:72:09:d2:87:10:cd:fd:4b:bb:88:28:
         ce:15:3e:d2
SHA256 Fingerprint=90:20:73:E9:33:D0:BF:9B:3D:A4:9A:3A:12:0D:0A:DE:CD:F0:31:96:0F:87:57:69:47:BD:C3:15:7C:D6:2D:8E
-----BEGIN CERTIFICATE-----
MIIDoTCCAomgAwIBAgIGDeDy02R2MA0GCSqGSIb3DQEBCwUAMCgxEjAQBgNVBAMM
CW1pdG1wcm94eTESMBAGA1UECgwJbWl0bXByb3h5MB4XDTE4MDUwODE5MTYxN1oX
DTIxMDUwOTE5MTYxN1owKDESMBAGA1UEAwwJbWl0bXByb3h5MRIwEAYDVQQKDAlt
aXRtcHJveHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCwkb72zGJf
/a+eSB65xVnKNvACp+ViSFwmG3jBOnQCD6+FdAzXJF+FTM7gmy8/CoW6jzY+vEs7
PBPYj7lGOEJpnLJ+UfrMq/xXlUmJRVyiF7ls/KP2DN9QnjYocR5D0ucTCuwl4V0n
pWldSHXyTEQ/ts0zottJ05dNTyxgrKBPSpYZUtlNuc5wSeYt65nGy0WMW995ChBT
RKzCo2z9faMEk3NeLtLZucnyXa2gaG65QzEuKzG1jSsJBHtjHnlaC8wCFn5sfgsE
0AfWO/lt+IDkteI2c+7CaqKzrSCsQgAkYa3/7Y0955827VGhkc8TYLRAHOSCKU7V
BUM2LQSyN8XLAgMBAAGjgdAwgc0wDwYDVR0TAQH/BAUwAwEB/zARBglghkgBhvhC
AQEEBAMCAgQweAYDVR0lBHEwbwYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcD
BAYIKwYBBQUHAwgGCisGAQQBgjcCARUGCisGAQQBgjcCARYGCisGAQQBgjcKAwEG
CisGAQQBgjcKAwMGCisGAQQBgjcKAwQGCWCGSAGG+EIEATAOBgNVHQ8BAf8EBAMC
AQYwHQYDVR0OBBYEFBiFQUxbzT8yC74S8shumHhutuozMA0GCSqGSIb3DQEBCwUA
A4IBAQCahDWMUIGuU0bNJTEkIjolo7DJvWjZfwY8iM0jDiQABlXGkQ+BqbYdPQFY
VIu85jjzCx37bNhnRtQOzFz/F6Tm0JXnjMOVTIBAUVu3MmUtUCUmC0rUnTVZ8NnM
HitURyQCZG3zAYUCyE59AhMwDJLIfEgqxt1kVF+OZc7GkSdh6cZRJfL09zN+SMUO
ocGGg2pahLc9cygLDFqY62QfqHL9ynE85ze0/5TOFT3V9OAYdUE8+WMBbt5zcx6/
4gLXR6ZKnnAtzgbEqeWlO7lf2LadM1j8OM77gAutXW9WYsqB0Sc2Xm8Deyt1Kb2F
080RozK3cgnShxDN/Uu7iCjOFT7S
-----END CERTIFICATE-----

keyhash: 3aae8d85450bae20aaf360d046bc0d90b2998800b3a7356f0742ef6a8824e423

=====================

keyfile: /home/tapioca/tapioca/.mitmproxy/mitmproxy-ca-cert.pem
x509text: 
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 15259797775478 (0xde0f2d36476)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=mitmproxy, O=mitmproxy
        Validity
            Not Before: May  8 19:16:17 2018 GMT
            Not After : May  9 19:16:17 2021 GMT
        Subject: CN=mitmproxy, O=mitmproxy
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:b0:91:be:f6:cc:62:5f:fd:af:9e:48:1e:b9:c5:
                    59:ca:36:f0:02:a7:e5:62:48:5c:26:1b:78:c1:3a:
                    74:02:0f:af:85:74:0c:d7:24:5f:85:4c:ce:e0:9b:
                    2f:3f:0a:85:ba:8f:36:3e:bc:4b:3b:3c:13:d8:8f:
                    b9:46:38:42:69:9c:b2:7e:51:fa:cc:ab:fc:57:95:
                    49:89:45:5c:a2:17:b9:6c:fc:a3:f6:0c:df:50:9e:
                    36:28:71:1e:43:d2:e7:13:0a:ec:25:e1:5d:27:a5:
                    69:5d:48:75:f2:4c:44:3f:b6:cd:33:a2:db:49:d3:
                    97:4d:4f:2c:60:ac:a0:4f:4a:96:19:52:d9:4d:b9:
                    ce:70:49:e6:2d:eb:99:c6:cb:45:8c:5b:df:79:0a:
                    10:53:44:ac:c2:a3:6c:fd:7d:a3:04:93:73:5e:2e:
                    d2:d9:b9:c9:f2:5d:ad:a0:68:6e:b9:43:31:2e:2b:
                    31:b5:8d:2b:09:04:7b:63:1e:79:5a:0b:cc:02:16:
                    7e:6c:7e:0b:04:d0:07:d6:3b:f9:6d:f8:80:e4:b5:
                    e2:36:73:ee:c2:6a:a2:b3:ad:20:ac:42:00:24:61:
                    ad:ff:ed:8d:3d:e7:9f:36:ed:51:a1:91:cf:13:60:
                    b4:40:1c:e4:82:29:4e:d5:05:43:36:2d:04:b2:37:
                    c5:cb
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            Netscape Cert Type: 
                SSL CA
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication, E-mail Protection, Time Stamping, Microsoft Individual Code Signing, Microsoft Commercial Code Signing, Microsoft Trust List Signing, Microsoft Server Gated Crypto, Microsoft Encrypted File System, Netscape Server Gated Crypto
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Subject Key Identifier: 
                18:85:41:4C:5B:CD:3F:32:0B:BE:12:F2:C8:6E:98:78:6E:B6:EA:33
    Signature Algorithm: sha256WithRSAEncryption
         9a:84:35:8c:50:81:ae:53:46:cd:25:31:24:22:3a:25:a3:b0:
         c9:bd:68:d9:7f:06:3c:88:cd:23:0e:24:00:06:55:c6:91:0f:
         81:a9:b6:1d:3d:01:58:54:8b:bc:e6:38:f3:0b:1d:fb:6c:d8:
         67:46:d4:0e:cc:5c:ff:17:a4:e6:d0:95:e7:8c:c3:95:4c:80:
         40:51:5b:b7:32:65:2d:50:25:26:0b:4a:d4:9d:35:59:f0:d9:
         cc:1e:2b:54:47:24:02:64:6d:f3:01:85:02:c8:4e:7d:02:13:
         30:0c:92:c8:7c:48:2a:c6:dd:64:54:5f:8e:65:ce:c6:91:27:
         61:e9:c6:51:25:f2:f4:f7:33:7e:48:c5:0e:a1:c1:86:83:6a:
         5a:84:b7:3d:73:28:0b:0c:5a:98:eb:64:1f:a8:72:fd:ca:71:
         3c:e7:37:b4:ff:94:ce:15:3d:d5:f4:e0:18:75:41:3c:f9:63:
         01:6e:de:73:73:1e:bf:e2:02:d7:47:a6:4a:9e:70:2d:ce:06:
         c4:a9:e5:a5:3b:b9:5f:d8:b6:9d:33:58:fc:38:ce:fb:80:0b:
         ad:5d:6f:56:62:ca:81:d1:27:36:5e:6f:03:7b:2b:75:29:bd:
         85:d3:cd:11:a3:32:b7:72:09:d2:87:10:cd:fd:4b:bb:88:28:
         ce:15:3e:d2
SHA256 Fingerprint=90:20:73:E9:33:D0:BF:9B:3D:A4:9A:3A:12:0D:0A:DE:CD:F0:31:96:0F:87:57:69:47:BD:C3:15:7C:D6:2D:8E
-----BEGIN CERTIFICATE-----
MIIDoTCCAomgAwIBAgIGDeDy02R2MA0GCSqGSIb3DQEBCwUAMCgxEjAQBgNVBAMM
CW1pdG1wcm94eTESMBAGA1UECgwJbWl0bXByb3h5MB4XDTE4MDUwODE5MTYxN1oX
DTIxMDUwOTE5MTYxN1owKDESMBAGA1UEAwwJbWl0bXByb3h5MRIwEAYDVQQKDAlt
aXRtcHJveHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCwkb72zGJf
/a+eSB65xVnKNvACp+ViSFwmG3jBOnQCD6+FdAzXJF+FTM7gmy8/CoW6jzY+vEs7
PBPYj7lGOEJpnLJ+UfrMq/xXlUmJRVyiF7ls/KP2DN9QnjYocR5D0ucTCuwl4V0n
pWldSHXyTEQ/ts0zottJ05dNTyxgrKBPSpYZUtlNuc5wSeYt65nGy0WMW995ChBT
RKzCo2z9faMEk3NeLtLZucnyXa2gaG65QzEuKzG1jSsJBHtjHnlaC8wCFn5sfgsE
0AfWO/lt+IDkteI2c+7CaqKzrSCsQgAkYa3/7Y0955827VGhkc8TYLRAHOSCKU7V
BUM2LQSyN8XLAgMBAAGjgdAwgc0wDwYDVR0TAQH/BAUwAwEB/zARBglghkgBhvhC
AQEEBAMCAgQweAYDVR0lBHEwbwYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcD
BAYIKwYBBQUHAwgGCisGAQQBgjcCARUGCisGAQQBgjcCARYGCisGAQQBgjcKAwEG
CisGAQQBgjcKAwMGCisGAQQBgjcKAwQGCWCGSAGG+EIEATAOBgNVHQ8BAf8EBAMC
AQYwHQYDVR0OBBYEFBiFQUxbzT8yC74S8shumHhutuozMA0GCSqGSIb3DQEBCwUA
A4IBAQCahDWMUIGuU0bNJTEkIjolo7DJvWjZfwY8iM0jDiQABlXGkQ+BqbYdPQFY
VIu85jjzCx37bNhnRtQOzFz/F6Tm0JXnjMOVTIBAUVu3MmUtUCUmC0rUnTVZ8NnM
HitURyQCZG3zAYUCyE59AhMwDJLIfEgqxt1kVF+OZc7GkSdh6cZRJfL09zN+SMUO
ocGGg2pahLc9cygLDFqY62QfqHL9ynE85ze0/5TOFT3V9OAYdUE8+WMBbt5zcx6/
4gLXR6ZKnnAtzgbEqeWlO7lf2LadM1j8OM77gAutXW9WYsqB0Sc2Xm8Deyt1Kb2F
080RozK3cgnShxDN/Uu7iCjOFT7S
-----END CERTIFICATE-----

private: False
protected: False
type: certificate

=====================

```
Here we can see public keys and X509 text output for certificates.

## APK Parsing
CERT Keyfinder started its life as part of the framework used to perform my [experiment to find private keys in Android apps](https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=517768). As such, Keyfinder includes the ability to parse Android application APK files.

### Simple APK Example
```
$ python3 keyfinder.py com.shopgate.android.app21760.apk 
Reached a NAMESPACE_END without having the namespace stored before? Prefix ID: 24, URI ID: 25
testapks/com.shopgate.android.app21760.apk distributes its signing key as: res/raw/keystore.jks
testapks/com.shopgate.android.app21760.apk includes private,protected key:  res/raw/keystore.jks (Java KeyStore)
testapks/com.shopgate.android.app21760.apk includes protected key:  res/raw/shopgate_bks_neu.bks (BouncyCastle Keystore V1)
test@test-virtual-machine:/mnt/v1/keyfinder$
```
Here we can see that the application in question includes a Java KeyStore file that is protected, and also that it includes a private key in it. Even thouth the Java KeyStore is protected with a password, the KeyStore file does *not* hide what the contents are. Keyfinder leverages this weakness to [change the KeyStore password](https://gist.github.com/zach-klippenstein/4631307) and then parse the contents using the native Java keytool utility. Also of interest in this case is the fact that the private key `res/raw/keystore.jks` contains the private key used to sign the Android application itself. Google indicates that [managing your key and keeping it secure are very important, both for you and for your users](https://developer.android.com/studio/publish/app-signing#manage-key), but in this case the application author has distributed it to the public!
### crt.sh Checking
For any key found by Keyfinder, the key's SHA256 signature is queried in the [crt.sh](https://crt.sh) website. This website monitors several [certificate transparency](https://en.wikipedia.org/wiki/Certificate_Transparency) sources to check whether a key or certificate has been seen in the wild. The usual reason for this is because an HTTPS web server is using a specified key or a certificate.
CERT Keyfinder will query crt.sh using two sources of information:
* The hash of a certificate that is located in a keystore that contains a private key
* The hash of a public key that has been extracted from a private key

When CERT Keyfinder reports that a key is located in crt.sh, this is likely a cause for concern. The reason for this concern is because a private key associated with a certificate listed in a certificate transparency database is likely a key that should not be accessible to the public. For example, any Android APK from the Google Play is obviously publicly available. This is not the place for a private key for an HTTPS website key
```
$ python3 keyfinder.py apks/ireland.numt.aplykey.apk
apks/ireland.numt.aplykey.apk includes private key:  assets/sample-keys/ca.key (pkcs5)
apks/ireland.numt.aplykey.apk includes private key:  assets/sample-keys/client.key (pkcs5)
Enter pass phrase for keys/ireland.numt.aplykey/assets/sample-keys/pass.key:apks/ireland.numt.aplykey.apk includes private,protected key:  assets/sample-keys/pass.key (pkcs5)
apks/ireland.numt.aplykey.apk includes protected key:  assets/sample-keys/pkcs12.p12 (pkcs12)
apks/ireland.numt.aplykey.apk includes private key:  assets/sample-keys/server.key (pkcs5)
apks/ireland.numt.aplykey.apk key assets/sample-keys/server.key is listed in crt.sh: https://crt.sh/?spkisha256=493f34228ad3179e2dad25a392acae4d2dcaebcf633240a9df9d7f4413c4e681
$
```
Here we can see that the file `assets/sample-keys/server.key` is listed in crt.sh as: [https://crt.sh/?spkisha256=493f34228ad3179e2dad25a392acae4d2dcaebcf633240a9df9d7f4413c4e681](https://crt.sh/?spkisha256=493f34228ad3179e2dad25a392acae4d2dcaebcf633240a9df9d7f4413c4e681]). Because this query is for a public key hash, rather than a certificate itself, we need to click through to any of the seen certificates to get details about what the private key may be used for. By clicking through to [https://crt.sh/?id=36943198](https://crt.sh/?id=36943198), we can see that the certificate was issued by Comodo CA Limited for the domain names `oxsv.meta-level.de` and `www.oxsv.meta-level.de`. Because this certificate expired in 2011, this issue is perhaps not terribly important. However, one might wonder how the private key `assets/sample-keys/server.key` ended up in a publicly-released Android application, and also was used by a publicly-available server. The impact of such a key leak may depend on how the server in question is being used.

### Key File Usage
Keyfinder includes another capability that can help to determine the functionality of a key used by an Android application. By using the `-u` option, Keyfinder will extract the APK contents using [apktool](https://ibotpeaches.github.io/Apktool/) and then check for APK contents that reference that key file. For example:
```
$ python3 keyfinder.py apks/by_sha256/06/14/49/06144936809844bcb120d360ecc148679e33fd013c2bdac8bd9d7b63d71a57a4/tntapp.trinitymember.apk -u
I: Using Apktool 2.3.1-dirty on tntapp.trinitymember.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /tmp/tntapp.trinitymember/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
res/raw/sm_private is referenced by extracted/tntapp.trinitymember/smali/tntapp/trinitymember/R$raw.smali
res/raw/sm_private is referenced by extracted/tntapp.trinitymember/res/values/public.xml
apks/by_sha256/06/14/49/06144936809844bcb120d360ecc148679e33fd013c2bdac8bd9d7b63d71a57a4/tntapp.trinitymember.apk includes private key:  res/raw/sm_private (pkcs5)

```
Here we can see that the Anrdoid code `R$raw.smali` makes reference to the `sm_private` key file. If we look at the `R$raw.smali` file, we can see one reference to sm_private:
```
.field public static final sm_private:I = 0x7f060001
```
If we look for `0x7f060001` in the application's code, we can see that it's referenced in `smali/tntapp/trinitymember/model/RSA.smali`
```
    const v18, 0x7f060001
    invoke-virtual/range {v17 .. v18}, Landroid/content/res/Resources;->openRawResource(I)Ljava/io/InputStream;
    move-result-object v7
    .line 114
    .local v7, "is":Ljava/io/InputStream;
    new-instance v3, Ljava/io/BufferedReader;
    new-instance v17, Ljava/io/InputStreamReader;
    const-string v18, "UTF-8"
    move-object/from16 v0, v17
    move-object/from16 v1, v18
...
```
smali code isn't too pretty to look at, so we can decompile the code into Java, which is a little more readable:
```java
    public static byte[] decryptRSA(Context arg20, String arg21) throws Exception {
        System.out.println(":" + arg21);
        byte[] v14 = Base64.decode(arg21.getBytes("UTF-8"), 0);
        BufferedReader v3 = new BufferedReader(new InputStreamReader(arg20.getResources().openRawResource(0x7F060001), "UTF-8"));
        ArrayList v13 = new ArrayList();
        while(true) {
            String v12 = v3.readLine();
            if(v12 == null) {
                break;
            }

            ((List)v13).add(v12);
        }
...
```
Here we can clearly see that we have a function called `decryptRSA`, which is opening the private key, which is referenced as resource `0x7F060001`. If we trace further into the application code, we can get a better idea of what the private key is being used for. But we'll leave that as an exercise for the reader.