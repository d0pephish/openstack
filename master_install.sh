#following this https://www.digitalocean.com/community/tutorials/how-to-set-up-an-openvpn-server-on-ubuntu-16-04
STARTDIR=$(pwd)
echo [+] First let\'s get some information. 
PUBLIC_IP=$(wget https://jianmin.ninja/ip.php -O - 2>/dev/null)
if [ -z "$PUBLIC_IP" ] ; then
   echo [-] could not determine public ip. 
   exit 1
fi;
echo [+] Detected public IP is ${PUBLIC_IP}
printf "Please enter the domain you are using>"
read -r DOMAIN_NAME
printf "Please enter the port you would like OpenVPN to use>"
read -r OPENVPN_PORT
printf "Please enter the Identity API URL to use>"
read -r OPENSTACK_IDENTITY_URL
OPENSTACK_DOMAIN=$(echo "${OPENSTACK_IDENTITY_URL}" | sed -e "s/[^/]*\/\/\([^@]*@\)\?\([^:/]*\).*/\2/")
OPENSTACK_IP=$(dig @8.8.8.8 ${OPENSTACK_DOMAIN} | grep -v '^$' | grep -v '^;' | awk ' { print $NF } ')
echo $OPENSTACK_DOMAIN $OPENSTACK_IP
printf "Please enter your Openstack domain (usually is default)>"
read -r OPENSTACK_LOGIN_DOMAIN
printf "Please enter your Openstack username>"
read -r OPENSTACK_LOGIN_USER
printf "Please enter your Openstack password>"
read -sr OPENSTACK_LOGIN_PASS
exit
echo [+] Installing openvpn...
apt-get update
apt-get install openvpn easy-rsa

mkdir /etc/openvpn/
make-cadir openvpn-ca
cd openvpn-ca
source vars
./clean-all
./build-ca
./build-key-server server
./build-dh
openvpn --genkey --secret keys/ta.key

#client key gen:
cd /etc/openvpn/openvpn-ca
source vars
./build-key client
cd /etc/openvpn/openvpn-ca/keys && cp ca.crt ca.key server.crt server.key ta.key dh2048.pem /etc/openvpn

cat << EOF > /etc/openvpn/server.conf
#################################################
# Sample OpenVPN 2.0 config file for            #
# multi-client server.                          #
#                                               #
# This file is for the server side              #
# of a many-clients <-> one-server              #
# OpenVPN configuration.                        #
#                                               #
# OpenVPN also supports                         #
# single-machine <-> single-machine             #
# configurations (See the Examples page         #
# on the web site for more info).               #
#                                               #
# This config should work on Windows            #
# or Linux/BSD systems.  Remember on            #
# Windows to quote pathnames and use            #
# double backslashes, e.g.:                     #
# "C:\\Program Files\\OpenVPN\\config\\foo.key" #
#                                               #
# Comments are preceded with '#' or ';'         #
#################################################

# Which local IP address should OpenVPN
# listen on? (optional)
;local a.b.c.d

# Which TCP/UDP port should OpenVPN listen on?
# If you want to run multiple OpenVPN instances
# on the same machine, use a different port
# number for each one.  You will need to
# open up this port on your firewall.
port ${OPENVPN_PORT}

# TCP or UDP server?
;proto tcp
proto udp

# "dev tun" will create a routed IP tunnel,
# "dev tap" will create an ethernet tunnel.
# Use "dev tap0" if you are ethernet bridging
# and have precreated a tap0 virtual interface
# and bridged it with your ethernet interface.
# If you want to control access policies
# over the VPN, you must create firewall
# rules for the the TUN/TAP interface.
# On non-Windows systems, you can give
# an explicit unit number, such as tun0.
# On Windows, use "dev-node" for this.
# On most systems, the VPN will not function
# unless you partially or fully disable
# the firewall for the TUN/TAP interface.
;dev tap
dev tun

# Windows needs the TAP-Win32 adapter name
# from the Network Connections panel if you
# have more than one.  On XP SP2 or higher,
# you may need to selectively disable the
# Windows firewall for the TAP adapter.
# Non-Windows systems usually don't need this.
;dev-node MyTap

# SSL/TLS root certificate (ca), certificate
# (cert), and private key (key).  Each client
# and the server must have their own cert and
# key file.  The server and all clients will
# use the same ca file.
#
# See the "easy-rsa" directory for a series
# of scripts for generating RSA certificates
# and private keys.  Remember to use
# a unique Common Name for the server
# and each of the client certificates.
#
# Any X509 key management system can be used.
# OpenVPN can also use a PKCS #12 formatted key file
# (see "pkcs12" directive in man page).
ca ca.crt
cert server.crt
key server.key  # This file should be kept secret

# Diffie hellman parameters.
# Generate your own with:
#   openssl dhparam -out dh2048.pem 2048
dh dh2048.pem

# Network topology
# Should be subnet (addressing via IP)
# unless Windows clients v2.0.9 and lower have to
# be supported (then net30, i.e. a /30 per client)
# Defaults to net30 (not recommended)
;topology subnet

# Configure server mode and supply a VPN subnet
# for OpenVPN to draw client addresses from.
# The server will take 10.8.0.1 for itself,
# the rest will be made available to clients.
# Each client will be able to reach the server
# on 10.8.0.1. Comment this line out if you are
# ethernet bridging. See the man page for more info.
server 172.20.25.0 255.255.255.0

# Maintain a record of client <-> virtual IP address
# associations in this file.  If OpenVPN goes down or
# is restarted, reconnecting clients can be assigned
# the same virtual IP address from the pool that was
# previously assigned.
ifconfig-pool-persist ipp.txt

# Configure server mode for ethernet bridging.
# You must first use your OS's bridging capability
# to bridge the TAP interface with the ethernet
# NIC interface.  Then you must manually set the
# IP/netmask on the bridge interface, here we
# assume 10.8.0.4/255.255.255.0.  Finally we
# must set aside an IP range in this subnet
# (start=10.8.0.50 end=10.8.0.100) to allocate
# to connecting clients.  Leave this line commented
# out unless you are ethernet bridging.
;server-bridge 10.8.0.4 255.255.255.0 10.8.0.50 10.8.0.100

#client config for static ip:
client-config-dir /etc/openvpn/ccd

# Configure server mode for ethernet bridging
# using a DHCP-proxy, where clients talk
# to the OpenVPN server-side DHCP server
# to receive their IP address allocation
# and DNS server addresses.  You must first use
# your OS's bridging capability to bridge the TAP
# interface with the ethernet NIC interface.
# Note: this mode only works on clients (such as
# Windows), where the client-side TAP adapter is
# bound to a DHCP client.
;server-bridge

# Push routes to the client to allow it
# to reach other private subnets behind
# the server.  Remember that these
# private subnets will also need
# to know to route the OpenVPN client
# address pool (10.8.0.0/255.255.255.0)
# back to the OpenVPN server.
push "route ${OPENSTACK_IP} 255.255.255.255"
;push "route 192.168.20.0 255.255.255.0"

# To assign specific IP addresses to specific
# clients or if a connecting client has a private
# subnet behind it that should also have VPN access,
# use the subdirectory "ccd" for client-specific
# configuration files (see man page for more info).

# EXAMPLE: Suppose the client
# having the certificate common name "Thelonious"
# also has a small subnet behind his connecting
# machine, such as 192.168.40.128/255.255.255.248.
# First, uncomment out these lines:
;client-config-dir ccd
;route 192.168.40.128 255.255.255.248
# Then create a file ccd/Thelonious with this line:
#   iroute 192.168.40.128 255.255.255.248
# This will allow Thelonious' private subnet to
# access the VPN.  This example will only work
# if you are routing, not bridging, i.e. you are
# using "dev tun" and "server" directives.

# EXAMPLE: Suppose you want to give
# Thelonious a fixed VPN IP address of 10.9.0.1.
# First uncomment out these lines:
;client-config-dir ccd
;route 10.9.0.0 255.255.255.252
# Then add this line to ccd/Thelonious:
#   ifconfig-push 10.9.0.1 10.9.0.2

# Suppose that you want to enable different
# firewall access policies for different groups
# of clients.  There are two methods:
# (1) Run multiple OpenVPN daemons, one for each
#     group, and firewall the TUN/TAP interface
#     for each group/daemon appropriately.
# (2) (Advanced) Create a script to dynamically
#     modify the firewall in response to access
#     from different clients.  See man
#     page for more info on learn-address script.
;learn-address ./script

# If enabled, this directive will configure
# all clients to redirect their default
# network gateway through the VPN, causing
# all IP traffic such as web browsing and
# and DNS lookups to go through the VPN
# (The OpenVPN server machine may need to NAT
# or bridge the TUN/TAP interface to the internet
# in order for this to work properly).
;push "redirect-gateway def1 bypass-dhcp"

# Certain Windows-specific network settings
# can be pushed to clients, such as DNS
# or WINS server addresses.  CAVEAT:
# http://openvpn.net/faq.html#dhcpcaveats
# The addresses below refer to the public
# DNS servers provided by opendns.com.
;push "dhcp-option DNS 208.67.222.222"
;push "dhcp-option DNS 208.67.220.220"

# Uncomment this directive to allow different
# clients to be able to "see" each other.
# By default, clients will only see the server.
# To force clients to only see the server, you
# will also need to appropriately firewall the
# server's TUN/TAP interface.
;client-to-client

# Uncomment this directive if multiple clients
# might connect with the same certificate/key
# files or common names.  This is recommended
# only for testing purposes.  For production use,
# each client should have its own certificate/key
# pair.
#
# IF YOU HAVE NOT GENERATED INDIVIDUAL
# CERTIFICATE/KEY PAIRS FOR EACH CLIENT,
# EACH HAVING ITS OWN UNIQUE "COMMON NAME",
# UNCOMMENT THIS LINE OUT.
;duplicate-cn

# The keepalive directive causes ping-like
# messages to be sent back and forth over
# the link so that each side knows when
# the other side has gone down.
# Ping every 10 seconds, assume that remote
# peer is down if no ping received during
# a 120 second time period.
keepalive 10 120

# For extra security beyond that provided
# by SSL/TLS, create an "HMAC firewall"
# to help block DoS attacks and UDP port flooding.
#
# Generate with:
#   openvpn --genkey --secret ta.key
#
# The server and each client must have
# a copy of this key.
# The second parameter should be '0'
# on the server and '1' on the clients.
tls-auth ta.key 0 # This file is secret
key-direction 0

# Select a cryptographic cipher.
# This config item must be copied to
# the client config file as well.
;cipher BF-CBC        # Blowfish (default)
cipher AES-128-CBC   # AES
auth SHA256
;cipher DES-EDE3-CBC  # Triple-DES

# Enable compression on the VPN link.
# If you enable it here, you must also
# enable it in the client config file.
comp-lzo

# The maximum number of concurrently connected
# clients we want to allow.
;max-clients 100

# It's a good idea to reduce the OpenVPN
# daemon's privileges after initialization.
#
# You can uncomment this out on
# non-Windows systems.
user nobody
group nogroup

# The persist options will try to avoid
# accessing certain resources on restart
# that may no longer be accessible because
# of the privilege downgrade.
persist-key
persist-tun

# Output a short status file showing
# current connections, truncated
# and rewritten every minute.
status openvpn-status.log

# By default, log messages will go to the syslog (or
# on Windows, if running as a service, they will go to
# the "\\Program Files\\OpenVPN\\log" directory).
# Use log or log-append to override this default.
# "log" will truncate the log file on OpenVPN startup,
# while "log-append" will append to it.  Use one
# or the other (but not both).
;log         openvpn.log
;log-append  openvpn.log

# Set the appropriate level of log
# file verbosity.
#
# 0 is silent, except for fatal errors
# 4 is reasonable for general usage
# 5 and 6 can help to debug connection problems
# 9 is extremely verbose
verb 3

# Silence repeating messages.  At most 20
# sequential messages of the same message
# category will be output to the log.
;mute 20
EOF

#static ip setup:
mkdir /etc/openvpn/ccd
printf "ifconfig-push 172.20.25.6 255.255.255.0\n" > /etc/openvpn/ccd/client

#gunzip -c /usr/share/doc/openvpn/examples/sample-config-files/server.conf.gz | tee /etc/openvpn/server.conf
#cd /etc/openvpn
#vim /etc/openvpn/server.conf
#//configure as necessary
#->change port to RHP
#->uncomment cipher AES-128-CBC
#-> add auth SHA256
#-> uncomment tls-auth 
#-> add key-direction 0
#-> uncomment user nobody, group nogroup
#-> push the route to your openstack infrastructure

#vim /etc/sysctl.conf
#-> net.ipv4.ip_forward=1
sed -i -e 's/net.ipv4.ip_forward=[01]/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sysctl -p


mkdir -p /etc/openvpn/client-configs/files
find /etc/openvpn -type d | xargs chmod 700

#client config
#cp /usr/share/doc/openvpn/examples/sample-config-files/client.conf /etc/openvpn/client-configs/client.conf
cat << EOF > /etc/openvpn/client-configs/base.conf
client
dev tun
proto udp
remote ${PUBLIC_IP} ${OPENVPN_PORT}
resolv-retry infinite
nobind
user nobody
group nogroup
persist-key
persist-tun
cipher AES-128-CBC
auth SHA256
key-direction 1
remote-cert-tls server
comp-lzo
verb 3
EOF

cat << EOF > /etc/openvpn/client-configs/newclient.sh
#!/bin/bash

# First argument: Client identifier

if [ -z "${1}" ] ; then
	echo missing arg1
	exit
fi;

KEY_DIR=/etc/openvpn/openvpn-ca/keys
OUTPUT_DIR=/etc/openvpn/client-configs/files
BASE_CONFIG=/etc/openvpn/client-configs/base.conf

cat \${BASE_CONFIG} \
    <(echo -e '<ca>') \
    \${KEY_DIR}/ca.crt \
    <(echo -e '</ca>\\n<cert>') \
    \${KEY_DIR}/\${1}.crt \
    <(echo -e '</cert>\\n<key>') \
    \${KEY_DIR}/\${1}.key \
    <(echo -e '</key>\\n<tls-auth>') \
    \${KEY_DIR}/ta.key \
    <(echo -e '</tls-auth>') \
    > \${OUTPUT_DIR}/\${1}.ovpn
EOF
chmod 700 /etc/openvpn/client-configs/newclient.sh

cd /etc/openvpn/client-configs
/etc/openvpn/client-configs/newclient.sh client
#/etc/openvpn/client-configs/files

#vim client.conf
#//remote 45.79.207.222 58667
#// user/group comments
#// suggested additions:
#ca ca.crt
#cert client.crt
#key client.key
#cipher AES-128-CBC
#auth SHA256
#key-direction 1
## script-security 2
## up /etc/openvpn/update-resolv-conf
## down /etc/openvpn/update-resolv-conf

#or use the script that digital ocean gives you

systemctl enable openvpn@server
systemctl start openvpn@server
systemctl status openvpn@server
#reverse portforward to vpn
apt-get install ufw -y

cat << EOF > /etc/ufw/before.rules
#
# rules.before
#
# Rules that should be run before the ufw command line added rules. Custom
# rules should be added to one of these chains:
#   ufw-before-input
#   ufw-before-output
#   ufw-before-forward
#
#DNAT 443
*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
#-F
-A PREROUTING -i eth0 -p tcp --dport 443 -j LOG --log-prefix portfwd:
-A PREROUTING -i eth0 -p tcp --dport 443 -j DNAT --to-destination 172.20.25.6
-A POSTROUTING -s 172.20.25.0/24 -o eth0 -j MASQUERADE
-A POSTROUTING -d 172.20.25.6 -j SNAT --to 172.20.25.1
COMMIT

# Don't delete these required lines, otherwise there will be errors
*filter
:ufw-before-input - [0:0]
:ufw-before-output - [0:0]
:ufw-before-forward - [0:0]
:ufw-not-local - [0:0]
# End required lines

# for vpn nat'ing
:ufw-before-forward - [0:0]
-A ufw-before-forward -i tun0 -o eth0 -s 172.20.25.0/24 -j ACCEPT
-A ufw-before-forward -i eth0 -o tun0 -p tcp --dport 443 -j ACCEPT

# allow all on loopback
-A ufw-before-input -i lo -j ACCEPT
-A ufw-before-output -o lo -j ACCEPT

# quickly process packets for which we already have a connection
-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-output -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-forward -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# drop INVALID packets (logs these in loglevel medium and higher)
-A ufw-before-input -m conntrack --ctstate INVALID -j ufw-logging-deny
-A ufw-before-input -m conntrack --ctstate INVALID -j DROP

# ok icmp codes for INPUT
-A ufw-before-input -p icmp --icmp-type destination-unreachable -j ACCEPT
-A ufw-before-input -p icmp --icmp-type source-quench -j ACCEPT
-A ufw-before-input -p icmp --icmp-type time-exceeded -j ACCEPT
-A ufw-before-input -p icmp --icmp-type parameter-problem -j ACCEPT
-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT

# ok icmp code for FORWARD
-A ufw-before-forward -p icmp --icmp-type destination-unreachable -j ACCEPT
-A ufw-before-forward -p icmp --icmp-type source-quench -j ACCEPT
-A ufw-before-forward -p icmp --icmp-type time-exceeded -j ACCEPT
-A ufw-before-forward -p icmp --icmp-type parameter-problem -j ACCEPT
-A ufw-before-forward -p icmp --icmp-type echo-request -j ACCEPT

# allow dhcp client to work
-A ufw-before-input -p udp --sport 67 --dport 68 -j ACCEPT

#
# ufw-not-local
#
-A ufw-before-input -j ufw-not-local

# if LOCAL, RETURN
-A ufw-not-local -m addrtype --dst-type LOCAL -j RETURN

# if MULTICAST, RETURN
-A ufw-not-local -m addrtype --dst-type MULTICAST -j RETURN

# if BROADCAST, RETURN
-A ufw-not-local -m addrtype --dst-type BROADCAST -j RETURN

# all other non-local packets are dropped
-A ufw-not-local -m limit --limit 3/min --limit-burst 10 -j ufw-logging-deny
-A ufw-not-local -j DROP

# allow MULTICAST mDNS for service discovery (be sure the MULTICAST line above
# is uncommented)
-A ufw-before-input -p udp -d 224.0.0.251 --dport 5353 -j ACCEPT

# allow MULTICAST UPnP for service discovery (be sure the MULTICAST line above
# is uncommented)
-A ufw-before-input -p udp -d 239.255.255.250 --dport 1900 -j ACCEPT

# don't delete the 'COMMIT' line or these rules won't be processed
COMMIT
EOF


#add following to beginning:
#*nat
#:PREROUTING ACCEPT [0:0]
#-A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 172.20.25.6:443
#-A POSTROUTING -j MASQUERADE
#COMMIT

ufw allow from 172.20.25.6 to 172.20.25.1 port 8080
ufw allow ${OPENVPN_PORT}/udp

ufw allow ssh
ufw enable
ufw status

cd ${STARTDIR}
apt-get install python python-pip -y
pip install --upgrade pip
pip install openstacksdk
pip install pyyaml
apt-get install gzip -y

OPENVPN_CLIENT_CERT="$(cat /etc/openvpn/client-configs/files/client.ovpn | gzip | base64 | awk 'BEGIN{ORS="\\n";} {print}')"
mkdir files
mkdir /etc/vpn_8080
mkdir /etc/vpn_8080/public
cat << EOF > /etc/vpn_8080/serv.py
import SimpleHTTPServer
import SocketServer
import os
os.chdir("/etc/vpn_8080/public")
PORT=8080
IP="172.20.25.1"
Handler = SimpleHTTPServer.SimpleHTTPRequestHandler

httpd = SocketServer.TCPServer((IP,PORT),Handler)

print "serving on: ",IP,PORT
httpd.serve_forever()
EOF

printf '#!/bin/sh\npython /etc/vpn_8080/serv.py ' > /bin/start8080python
chmod +x /bin/start8080python
printf '[Unit]\nDescription=VPN Python Web Server\n\n[Service]\nExecStart=/bin/start8080python\nUser=root\n\n[Install]\nWantedBy=multi-user.target\nAlias=vpnweb.service\n' > /lib/systemd/system/vpnweb.service 
systemctl enable vpnweb.service
systemctl start vpnweb.service


cat << EOF > /etc/vpn_8080/public/student_resources_server.init 
## First let's install ctfd 
apt-get update && apt-get upgrade -y && apt-get install git -y && mkdir /root/ctfd && cd /root/ctfd && git clone git@github.com:d0pephish/CTFd.git && cd CTFd && ./prepare.sh && printf '#!/bin/sh\ncd /root/ctfd/CTFd/\ngunicorn --bind 0.0.0.0:80 -w 1 "CTFd:create_app()"' > launchit.sh && chmod +x launchit.sh && printf '[Unit]\nDescription=CTFd Service\n\n[Service]\nExecStart=/root/ctfd/CTFd/launchit.sh\n\n[Install]\nWantedBy=multi-user.target\nAlias=ctfd.service\n' > /lib/systemd/system/ctfd.service && systemctl enable ctfd.service && systemctl start ctfd.service && apt-get install curl -y 

## Now we'll install the guacamole server
apt-get install guacamole-tomcat -y 
apt-get install libguac-client-ssh0 libguac-client-rdp0 -y

apt-get install -y pip
pip install openstacksdk

sed -i -e 's+window.location.href = "logout"+window.location.href = "../../"+g' /var/lib/tomcat8/webapps/guacamole/scripts/root-ui.js
sed -i -e 's+<button id="logout">Logout</button>+<button id="logout" style="display:none;visibility:hidden;">Back</button>+g' /var/lib/tomcat8/webapps/guacamole/index.xhtml
touch /var/lib/tomcat8/webapps/guacamole/WEB-INF/web.xml

## Now we'll install apache 
apt-get install apache2 -y
sed -e 's+^Listen 80+Listen 58080+' -i /etc/apache2/ports.conf


cat << EOFEMBED > /etc/apache2/sites-available/frontend.conf
<IfModule mod_ssl.c>

        <VirtualHost *:443>
                ServerName ${DOMAIN_NAME}

                DocumentRoot /var/www/html
                ServerAdmin admin@${DOMAIN_NAME}


                ErrorLog \${APACHE_LOG_DIR}/error.log
                CustomLog \${APACHE_LOG_DIR}/access.log combined


                SSLEngine on

                SSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem
                SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key


                <FilesMatch "\.(cgi|shtml|phtml|php)$">
                                SSLOptions +StdEnvVars
                </FilesMatch>
                <Directory /usr/lib/cgi-bin>
                                SSLOptions +StdEnvVars
                </Directory>

                BrowserMatch "MSIE [2-6]" \
                                nokeepalive ssl-unclean-shutdown \
                                downgrade-1.0 force-response-1.0
                BrowserMatch "MSIE [17-9]" ssl-unclean-shutdown


                <Location /guacamole/ >
                        ProxyPreserveHost On
                        ProxyPass "http://127.0.0.1:8080/guacamole/" flushpackets=on
                        ProxyPassReverse "http://127.0.0.1:8080/guacamole/"
                        ProxyPassReverseCookieDomain "${DOMAIN_NAME}" "127.0.0.1"
                        ProxyPassReverseCookiePath "/guacamole/" "http://127.0.0.1:8080/guacamole/"
						Header edit Location ^http(\:\/\/.*)$ https$1
                </Location>
                <Location /guacamole/websocket-tunnel>
                        ProxyPass "ws://127.0.0.1:8080/guacamole/websocket-tunnel"
                        ProxyPassReverse "ws://127.0.0.1:8080/guacamole/websocket-tunnel"
                </Location>


                <LocationMatch "^/(?!guacamole/)" >
                        ProxyPass http://127.0.0.1:80/
						Header edit Location ^http(\:\/\/.*)$ https$1
						ProxyPreserveHost On
                </LocationMatch >
        </VirtualHost>

</IfModule>
EOFEMBED

a2enmod ssl
a2enmod proxy
a2enmod proxy_http
a2enmod headers
a2dissite 000-default
a2ensite frontend
service apache2 restart

//ssl cert:
cd /root
wget https://dl.eff.org/certbot-auto
chmod a+x certbot-auto
#requires prompt
./certbot-auto --apache -m ben@${DOMAIN_NAME} --agree-tos -d ${DOMAIN_NAME} -n &
./certbot-auto renew --dry-run &
cat << EOFEMBED > /etc/cron.daily/letsencrypt
#!/bin/sh
/root/certbot-auto renew --quiet --no-self-upgrade
EOFEMBED
chmod +x /etc/cron.daily/letsencrypt


apt-get install ufw -y

##allow student network
ufw allow from 172.16.0.0/16 to any port 80
##allow remote management via vpn
ufw allow from 172.20.25.1 to any port 22
##allow remote https via frontend through vpn
ufw allow from 172.20.25.1 to any port 443
##allow exercise lane subnets to resource net
ufw allow from 192.168.0.0/16 to any port 9090

ufw enable

EOF


cat << EOF > files/deploy.py
from openstack import connection
import yaml, getpass

class openstacker:

    def __init__(self):
        self.conn = self.authenticate()

    def authenticate(self):
        conn = connection.Connection(auth_url="${OPENSTACK_IDENTITY_URL}",
                                     user_domain_name="${OPENSTACK_LOGIN_DOMAIN}",
                                     username="${OPENSTACK_LOGIN_USER}",
                                     password="${OPENSTACK_LOGIN_PASS}")
        return conn

    def deploy_yaml(self,params,template):
        self.conn.orchestration.create_stack(name="Student_"+str(num)+"_Station", template=template, parameters = params)

params = { "root_password" : getpass.getpass("Please enter your desired root password for the resources vm:")}
f = open("network.yaml", "r")
text = f.read()
f.close()
template_data = yaml.load(text)

new_lab = openstacker()
new_lab.deploy_yaml(params,template_data)
EOF
cat << EOF > files/network.yaml
heat_template_version: "2016-10-14"

description: Unit Exercise Persistent Network
# This script creates the persistent components of the exercise network.
# This should be deployed once to set up the environment. After this is deployed, another per-student deployment is required to build the student environment. Finally each exercise gets its own deployment script.
# First create network, then create subnet for that network. 
# For our uses there is a 1:1 relationship between a subnet and a network
# final step is to create a port (think physical interface) for specific vms

parameters:
  root_password:
    type: string
    label: Root Password
    description: Root password for student station
    default: "changeme"

resources:

## Some randomness 
  random-str:
    type: OS::Heat::RandomString
    properties:
      length: 20

#Student Workstation Network
#Contains the student workstation
  ex-stu-net:
    type: OS::Neutron::Net
    properties:
      name: ex_stu_net

  ex-stu-net-sub:
    type: OS::Neutron::Subnet
    properties:
      allocation_pools:
        - start: 172.16.0.100
          end: 172.16.254.254
      cidr: 172.16.0.0/16
      gateway_ip: 172.16.0.1
      network: { get_resource: ex-stu-net }
      name: ex_stu_net_sub
      dns_nameservers: [ 8.8.8.8 ]

#Student Resource Network
#Contains the server that students access for instructions for each scenario and to submit tokens after completion of exercise to unlock next scenario. 
  ex-stu-resource-net:
    type: OS::Neutron::Net
    properties:
      name: ex_stu_resource_net

  ex-stu-resource-net-sub:
    type: OS::Neutron::Subnet
    properties:
      allocation_pools:
        - start: 172.17.1.0
          end: 172.17.254.25
      cidr: 172.17.0.0/16
      gateway_ip: 172.17.0.254
      network: { get_resource: ex-stu-resource-net }
      name: ex_stu_resource_net_sub
      dns_nameservers: [ 8.8.8.8 ]


#Lane Resources
#Contains the server that will host all the individual exercise configuration scripts. Only routable from within exercise lane network.
  ex-lane-resource-net:
    type: OS::Neutron::Net
    properties:
      name: ex_lane_resource_net

  ex-lane-resource-net-sub:
    type: OS::Neutron::Subnet
    properties:
      allocation_pools:
        - start: 172.19.1.0
          end: 172.19.254.25
      cidr: 172.19.0.0/16
      gateway_ip: 172.19.0.254
      network: { get_resource: ex-lane-resource-net }
      name: ex_lane_resource_net_sub
      dns_nameservers: [ 8.8.8.8 ]


#Exercise Lane
#Individual exercise stacks will plug into this network 
  ex-lane-net:
    type: OS::Neutron::Net
    properties:
      name: ex_lane_net

  ex-lane-net-sub:
    type: OS::Neutron::Subnet
    properties:
      allocation_pools:
        - start: 172.18.1.0
          end: 172.18.254.25
      cidr: 172.18.0.0/16
      gateway_ip: 172.18.0.254
      network: { get_resource: ex-lane-net }
      name: ex_lane_net_sub
      dns_nameservers: [ 8.8.8.8 ]


### Persistent Router
#Provides student station, student resources, and exercise lane networks routes to each other and to the internet. 


  ex-primary-router:
    type: OS::Neutron::Router    
    properties:
      name: ex_primary_router
      external_gateway_info: {"network": public}

  ex-primary-router-stu-net-interface:
    type:  OS::Neutron::RouterInterface
    properties:
      router_id: { get_resource: ex-primary-router }       
      subnet_id: { get_resource: ex-stu-net-sub }


  ex-primary-router-lane-net-interface:
    type:  OS::Neutron::RouterInterface
    properties:
      router_id: { get_resource: ex-primary-router }       
      subnet_id: { get_resource: ex-lane-net-sub }

  ex-primary-router-stu-resource-net-interface:
    type:  OS::Neutron::RouterInterface
    properties:
      router_id: { get_resource: ex-primary-router }       
      subnet_id: { get_resource: ex-stu-resource-net-sub }

### Student Resource Server
# Hosts the server the student instructions and scoreboard server

# Network Ports:
  ex-stu-resource-net-ports-stu-resource-server:
    type: OS::Neutron::Port    
    properties:
      port_security_enabled: false
      network_id: { get_resource: ex-stu-resource-net }
      fixed_ips:
      - subnet_id: { get_resource: ex-stu-resource-net-sub }
        ip_address: 172.17.17.76

#Server
  ex-stu-resource-server:
    type: OS::Nova::Server
    properties:
      name: ex_stu_resource_server
      image: Debian Jessie
      flavor: cy.small
      networks:
        - port: { get_resource: ex-stu-resource-net-ports-stu-resource-server }
      user_data:
        str_replace:
          template: |
            #!/bin/bash
            echo "root:\$password" | chpasswd
            sed -i 's/localhost.*/localhost boxHostname/g' /etc/hosts
            echo boxHostname>/etc/hostname
            printf "${OPENVPN_CLIENT_CERT}" | base64 -d | gunzip > /root/openvpnclient.ovpn
            sleep 60 && echo "root:\$password" | chpasswd && echo password successfully changed to $password|| echo failed to change password &
            apt-get install openvpn -y && mv /root/openvpnclient.ovpn /etc/openvpn/client.conf && chmod 400 /etc/openvpn/client.conf && systemctl enable openvpn@client.service && systemctl start openvpn@client.service && sleep 60 && wget http://172.20.25.1:8080/student_resources_server.init -O - 2>/dev/null | /bin/bash
          params:
            \$password: { get_param: root_password}
            boxHostname: studentResources
      user_data_format: RAW



outputs:
 stu-net-uuid:
    description: student network uuid
    value: { get_resource : ex-stu-net }

 stu-net-sub-uuid:
    description: student network subnet uuid
    value: { get_resource : ex-stu-net-sub }

 lane-net-uuid:
    description: exercise lane net uuid
    value: { get_resource : ex-lane-net }

 lane-net-sub-uuid:
    description: exercise lane net sub uuid
    value: { get_resource : ex-lane-net-sub }
EOF
