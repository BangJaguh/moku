#!/bin/sh
curl -s https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
echo "deb http://build.openvpn.net/debian/openvpn/stable xenial main" > /etc/apt/sources.list.d/openvpn-aptrepo.list
apt-get update
apt-get -y install openvpn squid privoxy apache2 zip
ln -fs /usr/share/zoneinfo/Asia/Manila /etc/localtime
echo "net.ipv4.ip_forward=1" > /etc/sysctl.conf
cat > /etc/openvpn/server.conf <<-END
dev tun
proto tcp-server
port 110
dh none
tls-crypt tls-crypt.key 0
crl-verify crl.pem
ca ca.crt
cert server.crt
key server.key
client-cert-not-required
username-as-common-name
plugin /usr/lib/openvpn/plugins/openvpn-plugin-auth-pam.so login
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
keepalive 1 10
cipher none
auth none
reneg-sec 0
log /dev/null
status /dev/null
tcp-nodelay
ecdh-curve prime256v1
ncp-disable
tls-server
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
END
cat > /etc/rc.local <<-END
#!/bin/sh -e
echo "nameserver 1.1.1.1" > /etc/resolv.conf
echo "nameserver 1.0.0.1" >> /etc/resolv.conf
iptables -t nat -A POSTROUTING -j SNAT --to-source $(wget -qO- ipv4.icanhazip.com)
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
END
cat > /etc/openvpn/ca.crt <<-END
-----BEGIN CERTIFICATE-----
MIIBrTCCAVKgAwIBAgIJAMwxNnqzf5hxMAoGCCqGSM49BAMCMBcxFTATBgNVBAMM
DGplcm9tZWxhbGlhZzAeFw0xOTExMDEwNzUwMTBaFw0yOTEwMjkwNzUwMTBaMBcx
FTATBgNVBAMMDGplcm9tZWxhbGlhZzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA
BGALTkrNJ8w5KtpeIwjihLsLDXpZxv+KNpSQCei+n6JXvMPeKDrvwEvY8jsEb0KL
aqNbFDo0MfGc3d9OINRUttKjgYYwgYMwHQYDVR0OBBYEFJXihpO93UjCbxkAefFB
O8l4xb4rMEcGA1UdIwRAMD6AFJXihpO93UjCbxkAefFBO8l4xb4roRukGTAXMRUw
EwYDVQQDDAxqZXJvbWVsYWxpYWeCCQDMMTZ6s3+YcTAMBgNVHRMEBTADAQH/MAsG
A1UdDwQEAwIBBjAKBggqhkjOPQQDAgNJADBGAiEA8eehh3XGUwun5HYeW8Ao/vyy
X+9Xat9hIOVsXz/bosMCIQDoraPifMb6J2n0DyaOEfjN/R5JA6BRT0wjR+yBHPMv
pg==
-----END CERTIFICATE-----

END
cat > /etc/openvpn/crl.pem <<-END
-----BEGIN X509 CRL-----
MIHrMIGTAgEBMAoGCCqGSM49BAMCMBcxFTATBgNVBAMMDGplcm9tZWxhbGlhZxcN
MTkxMTAxMDc1MDEwWhcNMjkxMDI5MDc1MDEwWqBLMEkwRwYDVR0jBEAwPoAUleKG
k73dSMJvGQB58UE7yXjFviuhG6QZMBcxFTATBgNVBAMMDGplcm9tZWxhbGlhZ4IJ
AMwxNnqzf5hxMAoGCCqGSM49BAMCA0cAMEQCIFVhEmRNepS8dVlSjCSpR7312HCn
iNSruliDWnKkytbPAiAVhO4fjumH+XOdlMGeDT9iIOB36mIlOkTJF9b28RKXng==
-----END X509 CRL-----

END
cat > /etc/openvpn/server.crt <<-END
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            09:19:b9:24:66:46:b1:66:14:f0:72:31:0b:25:f7:db
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=jeromelaliag
        Validity
            Not Before: Nov  1 07:50:10 2019 GMT
            Not After : Oct 29 07:50:10 2029 GMT
        Subject: CN=jeromelaliag
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:16:26:9e:a9:45:57:9c:be:90:7c:36:b2:fa:9f:
                    fb:a0:04:2d:c1:e7:04:36:cf:c5:9a:0f:f8:0c:15:
                    9c:f4:84:19:c7:e9:55:81:61:e4:1c:a4:1f:d9:a0:
                    f0:ca:ff:41:04:65:4d:59:6b:aa:84:a4:31:a9:d1:
                    a6:f0:dc:43:a9
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Key Identifier: 
                D6:20:4D:1F:EC:C4:EC:7D:9A:91:AE:36:3F:A0:B0:BB:7C:27:EE:D3
            X509v3 Authority Key Identifier: 
                keyid:95:E2:86:93:BD:DD:48:C2:6F:19:00:79:F1:41:3B:C9:78:C5:BE:2B
                DirName:/CN=jeromelaliag
                serial:CC:31:36:7A:B3:7F:98:71

            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
            X509v3 Subject Alternative Name: 
                DNS:jeromelaliag
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:21:00:9a:ae:2f:c3:76:ac:78:9b:e3:79:93:e1:b3:
         ad:26:13:40:98:15:a6:6d:ba:a1:96:cc:5d:5a:03:33:5c:cf:
         e9:02:20:57:e8:61:3e:05:c9:c6:e1:fd:f2:c0:cd:47:5c:50:
         cb:5a:0e:79:01:a8:4f:63:2f:0b:22:b2:02:6a:8a:c5:8e
-----BEGIN CERTIFICATE-----
MIIB3jCCAYSgAwIBAgIQCRm5JGZGsWYU8HIxCyX32zAKBggqhkjOPQQDAjAXMRUw
EwYDVQQDDAxqZXJvbWVsYWxpYWcwHhcNMTkxMTAxMDc1MDEwWhcNMjkxMDI5MDc1
MDEwWjAXMRUwEwYDVQQDDAxqZXJvbWVsYWxpYWcwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAQWJp6pRVecvpB8NrL6n/ugBC3B5wQ2z8WaD/gMFZz0hBnH6VWBYeQc
pB/ZoPDK/0EEZU1Za6qEpDGp0abw3EOpo4GxMIGuMAkGA1UdEwQCMAAwHQYDVR0O
BBYEFNYgTR/sxOx9mpGuNj+gsLt8J+7TMEcGA1UdIwRAMD6AFJXihpO93UjCbxkA
efFBO8l4xb4roRukGTAXMRUwEwYDVQQDDAxqZXJvbWVsYWxpYWeCCQDMMTZ6s3+Y
cTATBgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBaAwFwYDVR0RBBAwDoIM
amVyb21lbGFsaWFnMAoGCCqGSM49BAMCA0gAMEUCIQCari/Ddqx4m+N5k+GzrSYT
QJgVpm26oZbMXVoDM1zP6QIgV+hhPgXJxuH98sDNR1xQy1oOeQGoT2MvCyKyAmqK
xY4=
-----END CERTIFICATE-----

END
cat > /etc/openvpn/server.key <<-END
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgnD6ovb/vyYsdARFN
eyp4QKd+mN26DTaqpI7noNIJbeehRANCAAQWJp6pRVecvpB8NrL6n/ugBC3B5wQ2
z8WaD/gMFZz0hBnH6VWBYeQcpB/ZoPDK/0EEZU1Za6qEpDGp0abw3EOp
-----END PRIVATE KEY-----

END
cat > /etc/openvpn/tls-crypt.key <<-END
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
945dd8355bf77ca1a5d13b6ca1a83ba7
d289338c5b6b3ae01a757741236b7ac7
dc51540a082f622afcca8ab63bc8cedb
e38978da6ba4da796aa93125ca319546
a3cec71c7407baa182a1e764f2dbda3a
d2b0f6aa2bcc7d83e5c89830414d90c1
7b8d3076512861ece9e08b9325c7b7f7
b64ffa9bb7f294731bd098076262fb31
5ef50d9f439d2eacb89b462cef97c34c
c3b5b2585003eaae2c6a88dd55a5ba9e
b05ce33b48bbe47703ca3bb3d0febd7c
f9a90018cbb63eb6f2678fa7169caac1
922fa5e26d76b1e1c0a762e7e0572841
89e86cdeaab657bb3a5a8d33d168c28f
12a5de0b41fb1a87484596f5bc440342
8a819b0cb1983c8dadea3a5faf42330a
-----END OpenVPN Static key V1-----

END
cat > /usr/bin/vpnuserlist <<-END
#!/bin/sh
if [ -z \$1 ]; then
for p in \$(awk -F: '{print \$1}' /etc/passwd); do chage -l \$p | echo \$p -\$(grep Account\ expires | sed 's/Account expires//g'); done | sed '/: never/d' | sed 's/\: //g'
else
chage -l \$1 | echo \$1 -\$(grep Account\ expires | sed 's/Account expires//g') | sed 's/\: //g'
fi
END
chmod 775 /usr/bin/vpnuserlist
cat > /usr/bin/vpnuseradd <<-END
#!/bin/sh
if [ -z "\$2" ];
then
echo "vpnuseradd <days> <username>"
else
useradd -s /bin/false -e \`date +%F -d "+\$1 days"\` \$2 > /dev/null 2>&1
echo Expiration: \`date "+%m/%d/%Y @ %T" -d "+\$1 days"\`
echo Username: \$2
passwd \$2
fi
END
chmod 775 /usr/bin/vpnuseradd
cat > /etc/privoxy/config <<-END
user-manual /usr/share/doc/privoxy/user-manual
confdir /etc/privoxy
logdir /var/log/privoxy
filterfile default.filter
logfile logfile
listen-address 0.0.0.0:8118
toggle 1
enable-remote-toggle 0
enable-remote-http-toggle 0
enable-edit-actions 0
enforce-blocks 0
buffer-limit 4096
enable-proxy-authentication-forwarding 1
forwarded-connect-retries 1
accept-intercepted-requests 1
allow-cgi-request-crunching 1
split-large-forms 0
keep-alive-timeout 5
tolerate-pipelining 1
socket-timeout 300
permit-access 0.0.0.0/0 $(wget -qO- ipv4.icanhazip.com)

END
cat > /etc/squid/squid.conf <<-END
acl localhost src 127.0.0.1/32 ::1
acl to_localhost dst 127.0.0.0/8 0.0.0.0/32 ::1
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT
acl SSH dst $(wget -qO- ipv4.icanhazip.com)-$(wget -qO- ipv4.icanhazip.com)/32
http_access allow SSH
http_access allow manager localhost
http_access deny manager
http_access allow localhost
http_access deny all
http_port 8080
coredump_dir /var/spool/squid
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname jeromelaliag

END
# Smart Prepaid - AT Promo OpenVPN Configuration
cat > /root/SMART-AT-PROMO.ovpn <<-END
client
dev tun
proto tcp-client
remote $(wget -qO- ipv4.icanhazip.com) 110
persist-key
persist-tun
auth-user-pass
verb 3
redirect-gateway def1
cipher none
auth none
auth-nocache
auth-retry interact
connect-retry 0 0
nice -20
reneg-sec 0
tls-client
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
dhcp-option DNS 1.1.1.1
dhcp-option DNS 1.0.0.1
http-proxy www.viber.com.edgekey.net.$(wget -qO- ipv4.icanhazip.com).gromedns.ml 8080
http-proxy-option CUSTOM-HEADER ""
http-proxy-option CUSTOM-HEADER "POST https://viber.com HTTP/1.0"
http-proxy-option CUSTOM-HEADER "Host viber.com"
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
<tls-crypt>
$(cat /etc/openvpn/tls-crypt.key)
</tls-crypt>
END
# Sun Prepaid - Text Unlimited 200 Promo OpenVPN Configuration
cat > /root/SUN-TU200.ovpn <<-END
client
dev tun
proto tcp-client
remote $(wget -qO- ipv4.icanhazip.com) 110
persist-key
persist-tun
auth-user-pass
verb 3
redirect-gateway def1
cipher none
auth none
auth-nocache
auth-retry interact
connect-retry 0 0
nice -20
reneg-sec 0
tls-client
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
dhcp-option DNS 1.1.1.1
dhcp-option DNS 1.0.0.1
http-proxy $(wget -qO- ipv4.icanhazip.com) 8080
http-proxy-option CUSTOM-HEADER CONNECT HTTP/1.0
http-proxy-option CUSTOM-HEADER Host line.telegram.me
http-proxy-option CUSTOM-HEADER X-Online-Host line.telegram.me
http-proxy-option CUSTOM-HEADER X-Forward-Host line.telegram.me
http-proxy-option CUSTOM-HEADER Connection keep-alive
http-proxy-option CUSTOM-HEADER Proxy-Connection keep-alive
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
<tls-crypt>
$(cat /etc/openvpn/tls-crypt.key)
</tls-crypt>
END
# Default No Proxy
cat > /root/DEFAULT-NO-PROXY.ovpn <<-END
client
dev tun
proto tcp-client
remote $(wget -qO- ipv4.icanhazip.com) 110
persist-key
persist-tun
auth-user-pass
verb 3
redirect-gateway def1
cipher none
auth none
auth-nocache
auth-retry interact
connect-retry 0 0
nice -20
reneg-sec 0
tls-client
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
dhcp-option DNS 1.1.1.1
dhcp-option DNS 1.0.0.1
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
<tls-crypt>
$(cat /etc/openvpn/tls-crypt.key)
</tls-crypt>
END
# Default With Proxy
cat > /root/DEFAULT-WITH-PROXY.ovpn <<-END
client
dev tun
proto tcp-client
remote $(wget -qO- ipv4.icanhazip.com) 110
persist-key
persist-tun
auth-user-pass
verb 3
redirect-gateway def1
cipher none
auth none
auth-nocache
auth-retry interact
connect-retry 0 0
nice -20
reneg-sec 0
tls-client
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
dhcp-option DNS 1.1.1.1
dhcp-option DNS 1.0.0.1
http-proxy $(wget -qO- ipv4.icanhazip.com) 8080
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
<tls-crypt>
$(cat /etc/openvpn/tls-crypt.key)
</tls-crypt>
END
# Sun Prepaid - Call and Text Combo 50 Promo, Text Unlimited 50 Promo OpenVPN Configuration
# Sun Postpaid - Fix Load Plan 300 OpenVPN Configuration
cat > /root/SUN-CTC50-TU50-FIXPLAN.ovpn <<-END
client
dev tun
proto tcp-client
remote $(wget -qO- ipv4.icanhazip.com) 110
persist-key
persist-tun
auth-user-pass
verb 3
redirect-gateway def1
cipher none
auth none
auth-nocache
auth-retry interact
connect-retry 0 0
nice -20
reneg-sec 0
tls-client
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
dhcp-option DNS 1.1.1.1
dhcp-option DNS 1.0.0.1
http-proxy e9413.g.akamaiedge.net.$(wget -qO- ipv4.icanhazip.com).gromedns.ml 8118
http-proxy-option VERSION 1.1
http-proxy-option CUSTOM-HEADER 'GET / HTTP/1.1'
http-proxy-option CUSTOM-HEADER 'Host: e9413.g.akamaiedge.net'
http-proxy-option CUSTOM-HEADER 'Upgrade-Insecure-Requests: 1'
http-proxy-option CUSTOM-HEADER 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36'
http-proxy-option CUSTOM-HEADER 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
http-proxy-option CUSTOM-HEADER 'Accept-Encoding: gzip, deflate'
http-proxy-option CUSTOM-HEADER 'Accept-Language: en'
http-proxy-option CUSTOM-HEADER 'Connection: keep-alive'
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
<tls-crypt>
$(cat /etc/openvpn/tls-crypt.key)
</tls-crypt>
END
# Globe Prepaid - Go Watch and Play Promo OpenVPN Configuration
cat > /root/GLOBE-TM-GOWATCHNPLAY.ovpn <<-END
client
dev tun
proto tcp-client
remote $(wget -qO- ipv4.icanhazip.com) 110
persist-key
persist-tun
auth-user-pass
verb 3
redirect-gateway def1
cipher none
auth none
auth-nocache
auth-retry interact
connect-retry 0 0
nice -20
reneg-sec 0
tls-client
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
dhcp-option DNS 1.1.1.1
dhcp-option DNS 1.0.0.1
http-proxy $(wget -qO- ipv4.icanhazip.com) 8080
http-proxy-option CUSTOM-HEADER CONNECT HTTP/1.0
http-proxy-option CUSTOM-HEADER Host www.googleapis.com
http-proxy-option CUSTOM-HEADER X-Online-Host www.googleapis.com
http-proxy-option CUSTOM-HEADER X-Forward-Host www.googleapis.com
http-proxy-option CUSTOM-HEADER Connection keep-alive
http-proxy-option CUSTOM-HEADER Proxy-Connection keep-alive
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
<tls-crypt>
$(cat /etc/openvpn/tls-crypt.key)
</tls-crypt>
END
# Smart Prepaid - Smart No Load OpenVPN Configuration
cat > /root/SMART-NO-LOAD.ovpn <<-END
client
dev tun
proto tcp-client
remote $(wget -qO- ipv4.icanhazip.com) 110
persist-key
persist-tun
auth-user-pass
verb 3
redirect-gateway def1
cipher none
auth none
auth-nocache
auth-retry interact
connect-retry 0 0
nice -20
reneg-sec 0
tls-client
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
dhcp-option DNS 1.1.1.1
dhcp-option DNS 1.0.0.1
http-proxy billspaypromos.smart.com.ph.$(wget -qO- ipv4.icanhazip.com).gromedns.ml 8118
http-proxy-option CUSTOM-HEADER ""
http-proxy-option CUSTOM-HEADER "POST https://billspaypromos.smart.com.ph HTTP/1.0"
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
<tls-crypt>
$(cat /etc/openvpn/tls-crypt.key)
</tls-crypt>
END
cd /root/
rm -rf /var/www/html/config.zip
zip /var/www/html/config.zip SMART-NO-LOAD.ovpn SMART-AT-PROMO.ovpn SUN-TU200.ovpn SUN-CTC50-TU50-FIXPLAN.ovpn GLOBE-TM-GOWATCHNPLAY.ovpn DEFAULT-NO-PROXY.ovpn DEFAULT-WITH-PROXY.ovpn
rm /root/*

# Configure Nginx
sed -i 's/\/var\/www\/html;/\/home\/vps\/public_html\/;/g' /etc/nginx/sites-enabled/default
cp /var/www/html/index.nginx-debian.html /home/vps/public_html/index.html
mkdir -p /home/vps/public_html
cat > /home/vps/public_html/index.html <<-END
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Embex VPN</title>
        <meta name="description" content="Use Embex VPN for free!" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <!--Bootstrap 4-->
        <link rel="stylesheet" href="css/bootstrap.min.css">
        <link rel="stylesheet" href="https://raw.githubusercontent.com/radzvpn/TNTNOLOADDNS/master/animate.min.css">
        <!--icons-->
        <link rel="stylesheet" href="https://raw.githubusercontent.com/radzvpn/TNTNOLOADDNS/master/ionicons.min.css" />
    </head>
    <body>
        <!--header-->
        <nav class="navbar navbar-expand-md navbar-dark fixed-top sticky-navigation">
            <button class="navbar-toggler navbar-toggler-right" type="button" data-toggle="collapse" data-target="#navbarCollapse" aria-controls="navbarCollapse" aria-expanded="false" aria-label="Toggle navigation">
                <span class="ion-grid icon-sm"></span>
            </button>
            <a class="navbar-brand hero-heading" href="#">Embex VPN</a>
            <div class="collapse navbar-collapse" id="navbarCollapse">
                <ul class="navbar-nav ml-auto">
                    <li class="nav-item mr-3">
                        <a class="nav-link page-scroll" href="#main">Home<span class="sr-only">(current)</span></a>
                    </li>
                    <li class="nav-item mr-3">
                        <a class="nav-link page-scroll" href="#features">Features</a>
                    </li>
                    <li class="nav-item mr-3">
                        <a class="nav-link page-scroll" href="#configs">Configs</a>
                    </li>
                    <li class="nav-item mr-3">
                        <a class="nav-link page-scroll" href="#download">VPN App</a>
                    </li>
					<li class="nav-item mr-3">
                        <a class="nav-link page-scroll" href="#team">Our Team</a>
                    </li>
                    <li class="nav-item mr-3">
                        <a class="nav-link page-scroll" href="#links">Links</a>
                    </li>
                    <li class="nav-item mr-3">
                        <a class="nav-link page-scroll" href="#contact">Contact</a>
                    </li>
                </ul>
            </div>
        </nav>

        <!--main section-->
        <section class="bg-texture hero" id="main">
            <div class="container">
                <div class="row d-md-flex brand">
                    <div class="col-md-6 hidden-sm-down wow fadeIn">
                        <img class="img-fluid mx-auto d-block" src="img/product.png"/>
                    </div>
                    <div class="col-md-6 col-sm-12 text-white wow fadeIn">
                        <h2 class="pt-4">Experience <b class="text-primary-light">Embex VPN </b> for FREE</h2>
                        <p class="mt-5">
                            The best gets even better. With our swift and fastest low ping private server, you'll not being worried again with our vpn services.
                        </p>
                        <p class="mt-5">
                            <a href="#configs" class="btn btn-primary mr-2 mb-2 page-scroll">Try Now</a>
                            <a href="#download" class="btn btn-white mb-2 page-scroll">Download App</a>
                        </p>
                    </div>
                </div>
            </div>
        </section>

        <!--features-->
        <section class="bg-light" id="features">
            <div class="container">
                <div class="row mb-3">
                    <div class="col-md-6 col-sm-8 mx-auto text-center wow fadeIn">
                        <h2 class="text-primary">Amazing Features of Embex VPN</h2>
                        <p class="lead mt-4">
                            A plenty of awesome features to <br/>wow the users.
                        </p>
                    </div>
                </div>
                <div class="row mt-5 text-center">
                    <div class="col-md-4 wow fadeIn">
                        <div class="card">
                            <div class="card-body">
                                <div class="icon-box">
                                    <em class="ion-ios-game-controller-b-outline icon-md"></em>
                                </div>
                                <h6>Unlimited Gaming</h6>
                                <p>
                                    Low ping & Optimized server for your best unlimited gaming experience. 
                                </p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4 wow fadeIn">
                        <div class="card">
                            <div class="card-body">
                                <div class="icon-box">
                                    <em class="ion-android-wifi icon-md"></em>
                                </div>
                                <h6>Cloudflare DNS</h6>
                                <p>
                                    With the best DNS installed in our server to keep your connection at stable, streaming faster, download accelerated, & uploading boosted. 
                                </p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4 wow fadeIn">
                        <div class="card">
                            <div class="card-body">
                                <div class="icon-box">
                                    <em class="ion-ios-settings icon-md"></em>
                                </div>
                                <h6>Advanced Configs</h6>
                                <p>
                                    All our SSH/OVPN/DROPBEAR/SSL are highly configurable to meet your VPN experience & satisfaction. 
                                </p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4 wow fadeIn">
                        <div class="card">
                            <div class="card-body">
                                <div class="icon-box">
                                    <em class="ion-ios-cloud-upload-outline icon-md"></em>
                                </div>
                                <h6>Unlimited Bandwidth</h6>
                                <p>
                                    No capping and you can download/stream/browse all what you want without limitations. 
                                </p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4 wow fadeIn">
                        <div class="card">
                            <div class="card-body">
                                <div class="icon-box">
                                    <em class="ion-ios-locked-outline icon-md"></em>
                                </div>
                                <h6>Highly Secure</h6>
                                <p>
                                    Our server is from best VPS Cloud service, with anti-torrent & anti-ddos installed for our servers go for a longer last. 
                                </p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4 wow fadeIn">
                        <div class="card">
                            <div class="card-body">
                                <div class="icon-box">
                                    <em class="ion-android-color-palette icon-md"></em>
                                </div>
                                <h6>More Features & Colors</h6>
                                <p>
                                    With more future plans coming to keep this server colored and beautiful. 
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <section class="bg-white p-0">
            <div class="container-fluid">
                <div class="row d-md-flex mt-5">
                    <div class="col-sm-6 p-0 wow fadeInLeft">
                        <img class="img-fluid" src="img/whyus.png" alt="Why we Choose us">
                    </div>
                    <div class="col-sm-6 pl-5 pr-5 pt-5 pb-4 wow fadeInRight">
                        <h3><a href="#"></a></h3>
                        <p class="lead pt-4">VPN (virtual private network) is a technology that could make internet access you comfortable with eliminating prevention in accessing all sites. Giving new anonymous identity, disguise your original location and encrypts all traffic, such things make all data access and secure internet. Internet service provider or network operator, even the government, will not be able to check or filter your activity on the web.</p>
						Why you choose Embex VPN?
                        <ul class="pt-4 pb-3 list-default">
                            <li><font color="green"><b>FREE at all</b></font></li>
                            <li>Anonymous</li>
                            <li>Safe</li>
                            <li>Fast</li>
                            <li>Low Ping</li>
                            <li>Smooth</li>
                            <li>The best of the BEST!</li>
                        </ul>
                        <a href="#configs" class="btn btn-primary mr-2 page-scroll">Get Started with Embex VPN</a>
                    </div>
                </div>
            </div>
        </section>

        <!--pricing-->
        <section class="bg-light" id="configs">
            <div class="container">
                <div class="row">
                    <div class="col-md-6 offset-md-3 col-sm-8 offset-sm-2 col-xs-12 text-center">
                        <h2 class="text-primary">Configs</h2>
                        <p class="lead pt-3">
                            Our OpenVPN configs.
                        </p>
                    </div>
                </div>
                <div class="row d-md-flex mt-4 text-center">
                    <div class="col-sm-4 mt-4 wow fadeIn">
                        <div class="card">
                            <div class="card-body">
                                <h5 class="card-title pt-4 text-orange">OpenVPN</h5>
                                <h3 class="card-title text-primary pt-4">TCP</h3>
                                <p class="card-text text-muted pb-3 border-bottom">Default Config</p>
                                <ul class="list-unstyled pricing-list">
                                    <li>Port: 1153</li>
                                    <li>TCP Connection</li>
                                    <li>Stable</li>
                                    <li>Fast &amp; Smooth</li>
                                </ul>
                                <a href="/client.ovpn" class="btn btn-primary btn-radius">Download</a>
                            </div>
                        </div>
                    </div>
                    <div class="col-sm-4 mt-0 wow fadeIn">
                        <div class="card pt-4 pb-4">
                            <div class="card-body">
                                <h5 class="card-title pt-4 text-orange">OpenVPN</h5>
                                <h3 class="card-title text-primary pt-4"><sup></sup>SSL</h3>
                                <p class="card-text text-muted pb-3 border-bottom">Default config</p>
                                <ul class="list-unstyled pricing-list">
                                    <li>Port: 443</li>
                                    <li>OpenVPN over SSL</li>
                                    <li>Stable</li>
                                    <li>Fast &amp; Smooth</li>
                                </ul>
                                <a href="/clientssl.ovpn" class="btn btn-primary btn-radius">Download</a>
                            </div>
                        </div>
                    </div>
                    <div class="col-sm-4 mt-4 wow fadeIn">
                        <div class="card">
                            <div class="card-body">
                                <h5 class="card-title pt-4 text-orange">OpenVPN Package <small class="badge bg-primary small-xs">HOT</small></h5>
                                <h3 class="card-title text-primary pt-4"><sup></sup>Combo</h3>
                                <p class="card-text text-muted pb-3 border-bottom">zip packed</p>
                                <ul class="list-unstyled pricing-list">
                                    <li>TCP &amp; SSL</li>
                                    <li>With stunnel.conf</li>
                                    <li>For modem used</li>
                                    <li>Zip packed</li>
                                </ul>
                                <a href="/openvpn.zip" class="btn btn-primary btn-radius">Download</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!--download-->
        <section class="bg-orange pt-0" id="download">
            <div class="container">
                <div class="row d-md-flex text-center wow fadeIn">
                    <div class="col-md-6 offset-md-3 col-sm-10 offset-sm-1 col-xs-12">
                        <h5 class="text-primary">Download Our Mobile App</h5>
                        <p class="mt-4">
                            Download our provided apps for free for your android phone & pc.
                            
                        <p class="mt-5">
                            RADZ VPN<br><a href="https://play.google.com/store/apps/details?id=youpz.vpn.ssh" class="mr-2" target="_blank"><img src="img/google-play.png" class="store-img"/></a><br>
                            WENZ VPN<br><a href="https://play.google.com/store/apps/details?id=wenz.soft.dev.wenzvpn" class="mr-2" target="_blank"><img src="img/google-play.png" class="store-img"/></a><br>
                            Configs PH<br><a href="https://play.google.com/store/apps/details?id=fb.com.nicanor03" class="mr-2" target="_blank"><img src="img/google-play.png" class="store-img"/></a><br>
							<br>FOR PC<br><a href="https://www.phcorner.net/threads/685100/" target="_blank">Uni OVPN (&#169; JustPlaying)</a>
                        </p>
                    </div>
                </div>
            </div>
        </section>

        <!--team-->
        <section class="bg-white" id="team">
            <div class="container">
                <div class="row">
                    <div class="col-md-6 col-sm-8 mx-auto text-center">
                        <h2 class="text-primary">Our Team</h2>
                        <p class="lead pt-3">
                            Meet our awesome team.
                        </p>
                    </div>
                </div>
                <div class="row d-md-flex mt-5 text-center">
                    <div class="team col-sm-3 mt-2 wow fadeInLeft">
                        <img src="img/team-1.gif" alt="Owner" class="img-team img-fluid rounded-circle"/>
                        <h5>Embex | KDS</h5>
                        <p>Developer, Owner</p>
                    </div>
                    <div class="team col-sm-3 mt-2 wow fadeIn">
                        <img src="img/team-2.jpg" alt="Team Epiphany" class="img-team img-fluid rounded-circle"/>
                        <h5>Team Epiphany</h5>
                        <p>Our Official Group Name</p>
                    </div>
                    <div class="team col-sm-3 mt-2 wow fadeIn">
                        <img src="img/team-3.gif" alt="Embex" class="img-team img-fluid rounded-circle"/>
                        <h5>EMBEX TEAM</h5>
                        <p>Partner Team</p>
                    </div>
                    <div class="team col-sm-3 mt-2 wow fadeInRight">
                        <img src="img/team-4.png" alt="Team Unstoppable" class="img-team img-fluid rounded-circle"/>
                        <h5>Team Unstoppable</h5>
                        <p>Partner Team</p>
                    </div>
                </div>
            </div>
        </section>

        <!--blog-->
        <section class="bg-light" id="links">
            <div class="container">
                <div class="row">
                    <div class="col-md-6 offset-md-3 col-sm-8 offset-sm-2 col-xs-12 text-center">
                        <h2 class="text-primary">Links</h2>
                        <p class="lead pt-3">
                            Our recommended and partner sites.
                        </p>
                    </div>
                </div>
                <div class="row d-md-flex mt-5">
                    <div class="col-sm-4 mt-2 wow fadeIn">
                        <div class="card">
                            <img class="card-img-top" src="img/pt.png" alt="PinoyThread">
                            <div class="card-body">
                                <p class="card-text text-muted small-xl">
                                    <em class="ion-ios-calendar-outline"></em>&nbsp;&nbsp;
                                    <em class="ion-ios-person-outline"></em>  &nbsp;&nbsp;
                                    <em class="ion-ios-time-outline"></em>
                                </p>
                                <h5 class="card-title"><a href="https://www.pinoythread.com" target="_blank">Join PinoyThread Forum!</a></h5>
                                <p class="card-text">Welcome to PinoyThread. Come and join discuss about the pinoy cyber world.<br>FREE VPNs<br>Giveaways<br>Droplets<br>more...</p>
                            </div>
                            <div class="card-body text-right">
                                <a href="https://www.pinoythread.com" class="card-link" target="_blank"><strong>Join now</strong></a>
                            </div>
                        </div>
                    </div>
                    <div class="col-sm-4 mt-2 wow fadeIn">
                        <div class="card">
                            <img class="card-img-top" src="img/radz.png" alt="RADZ VPN">
                            <div class="card-body">
                                <p class="card-text text-muted small-xl">
                                    <em class="ion-ios-calendar-outline"></em> &nbsp;&nbsp;
                                    <em class="ion-ios-person-outline"></em> &nbsp;&nbsp;
                                    <em class="ion-ios-time-outline"></em>
                                </p>
                                <h5 class="card-title"><a href="https://radzvpn.ml/" target="_blank">Finally! RADZ VPN</a></h5>
                                <p class="card-text">New Web Design<br>
								Can create up to 50 accounts every server per day<br>
								3 VIP Fast Servers Available<br>
								Fast and Easy to create account<br>
								Customer Service Chat Box Plugins<br>
								You can able to check your account info</p>
                            </div>
                            <div class="card-body text-right">
                                <a href="https://radzvpn.ml/" class="card-link"target="_blank"><strong>Visit now</strong></a>
                            </div>
                        </div>
                    </div>
                    <div class="col-sm-4 mt-2 wow fadeIn">
                        <div class="card">
                            <img class="card-img-top" src="img/te.jpg" alt="Our Discord server">
                            <div class="card-body">
                                <p class="card-text text-muted small-xl">
                                    <em class="ion-ios-calendar-outline"></em>&nbsp;&nbsp;
                                    <em class="ion-ios-person-outline"></em> &nbsp;&nbsp;
                                    <em class="ion-ios-time-outline"></em>
                                </p>
                                <h5 class="card-title"><a href="https://discord.gg/EHq4XjH" target="_blank">The TEAM Epiphany</a></h5>
                                <p class="card-text"><b>TEAM Epiphany<b> is now live on Discord with...<br>
								VPN Scripts<br>
								Daily Giveaways<br>
								Friendly members<br>
								VPN Configs<br>
								Source Codes<br>
								Bins & VPS<br>
								A tons of richness of features<br>
								that you can't find here!</p>
                            </div>
                            <div class="card-body text-right">
                                <a href="https://discord.gg/EHq4XjH" class="card-link" target="_blank"><strong>Connect to them</strong></a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!--contact-->
        <section class="bg-texture-collage p-0" id="contact">
            <div class="container">
                <div class="row d-md-flex text-white text-center wow fadeIn">
                    <div class="col-sm-4 p-5">
                        <p><em class="ion-ios-telephone-outline icon-md"></em></p>
                        <p class="lead"><a href="https://discord.gg/EHq4XjH" target="_blank"><font color="#0000EE">Discord</font></a></p>
                    </div>
                    <div class="col-sm-4 p-5">
                        <p><em class="ion-ios-email-outline icon-md"></em></p>
                        <p class="lead">Embex@embex.online</p>
                    </div>
                    <div class="col-sm-4 p-5">
                        <p><em class="ion-ios-location-outline icon-md"></em></p>
                        <p class="lead">Jakarta, ID</p>
                    </div>
                </div>
            </div>
        </section>

        <!--footer-->
        <section class="bg-footer" id="connect">
            <div class="container">
                <div class="row">
                    <div class="col-md-6 offset-md-3 col-sm-8 offset-sm-2 col-xs-12 text-center wow fadeIn">
                        <h1>Embex VPN</h1>
			<br>
			<iframe src="https://discordapp.com/widget?id=499555022078607360&amp;theme=dark" width="350" height="500" allowtransparency="true" frameborder="0"></iframe>
			<br>
                        <p class="mt-4">
                            <a href="https://discord.gg/EHq4XjH" target="_blank"><img src="img/discord.png" alt="Our Discord server"/></a>   
                            <a href="https://www.facebook.com/RADZ-VPN-260317881583057" target="_blank"><img src="img/facebook.png" alt="Our Facebook"/></a>
                           
                        </p>
                        <p class="pt-2 text-muted">
                            &copy; 2019 <a href="http://www.phcorner.net/members/446411/" target="_blank">Embex</a>
                        </p>
                    </div>
                </div>
            </div>
        </section>

        <script src="https://raw.githubusercontent.com/radzvpn/TNTNOLOADDNS/master/jquery-3.1.1.min.js></script>
        <script src="https://raw.githubusercontent.com/radzvpn/TNTNOLOADDNS/master/umdpopper.min.js"></script>
        <script src="//maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta.2/js/bootstrap.min.js"></script>
        <script src="https://raw.githubusercontent.com/radzvpn/TNTNOLOADDNS/master//jquery.easing.min.js"></script>
        <script src="https://raw.githubusercontent.com/radzvpn/TNTNOLOADDNS/master/wow.js"></script>
        <script src="js/scripts.js"></script>
    </body>
</html>
END

# Unpack Embex homepage
cd /home/vps/public_html
wget "https://raw.githubusercontent.com/radzvpn/TNTNOLOADDNS/master/hiratechihomepage.zip"
unzip hiratechihomepage.zip
rm hiratechihomepage.zip
cd

# Finish Logs
clear
echo VPS Open Ports
echo OpenSSH Port: 22
echo Apache2 Port: 80
echo OpenVPN Port: 110
echo Squid Port: 8080
echo Privoxy Port: 8118
echo
echo Download your openvpn config here.
echo "http://$(wget -qO- ipv4.icanhazip.com)/config.zip"
echo
echo Rebooting...
reboot
