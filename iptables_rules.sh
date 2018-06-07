#!/bin/sh

# These commands work for creating the iptables rules

# first defatul to ACCEPT,
sudo iptables -P INPUT ACCEPT
# thsn FLUSH before rewriting the rules
sudo iptables -F INPUT


sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# This rule is a SECURITY RULE to mitigate potential risk
sudo iptables -A INPUT -j DROP -p tcp -s 172.18.30.89/32 --dport 1:65535
sudo iptables -A INPUT -j DROP -p udp -s 172.18.30.89/32 --dport 1:65535
# 20150916 blocking all ports to/from 10.40.101.241 due to drive mapping taking up space
#  a quick and dirty workaround because we cant seem to delete this mapping consuming space
#  df -k yields
#      //10.40.101.241/client   1682938238  67177904 1481125276   5% /home/cxraygada/testDrive
sudo iptables -A INPUT -j DROP -p tcp -s 10.40.101.241/32 --dport 1:65525
sudo iptables -A INPUT -j DROP -p udp -s 10.40.101.241/32 --dport 1:65525


###  Rules for Vulnerability testing using MIA-SCAN-PAPP01 Rapid7 Scanner 20170410
sudo iptables -A INPUT -j ACCEPT -p icmp -s 10.3.120.35/32 -d 0/0

sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.3.120.35/32 --dport 3306
#sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.3.120.35/32 --dport 21
#sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.3.120.35/32 --dport 22

sudo iptables -A INPUT -j DROP -p tcp -s 10.3.120.35/32 --dport 1:65525
sudo iptables -A INPUT -j DROP -p udp -s 10.3.120.35/32 --dport 1:65525


# These rules at the very top are to allow TTCP to work
# TTCP is a tool for Testing TCP
#  (see http://www.pcausa.com/Utilities/pcattcp.htm) 
sudo iptables -A INPUT -j ACCEPT -p tcp --dport 5001
sudo iptables -A INPUT -j ACCEPT -p udp --dport 5001



# Putting this one in here to block excessive error alerts 6-17-06
# sudo iptables -A INPUT -j DROP -p udp -s 10.1.201.122 --dport 514
sudo iptables -A INPUT -j ACCEPT -p udp --dport 514

sudo iptables -A INPUT -j ACCEPT -p udp --dport 162
#sudo iptables -A INPUT -j ACCEPT -p udp --dport tftp

# FTP rule
sudo iptables -A INPUT -j ACCEPT -p tcp --dport 20
sudo iptables -A INPUT -j ACCEPT -p tcp --dport 21
#sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.3.252.0/24  --dport 1:65535
#sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.56.101.0/23  --dport 1:65535
#sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.56.252.0/24  --dport 1:65535
#sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.3.101.25/32  --dport 1:65535
#sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.64.80.74/32  --dport 1:65535
#sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.64.101.31/32  --dport 1:65535
#sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.58.101.228/32  --dport 1:65535
#sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.57.101.7/32  --dport 1:65535

sudo iptables -A INPUT -j ACCEPT -p tcp --dport 22
#sudo iptables -A INPUT -j ACCEPT -p tcp --dport 23
sudo iptables -A INPUT -j ACCEPT -p tcp --dport 25
sudo iptables -A INPUT -j ACCEPT -p tcp --dport 80
sudo iptables -A INPUT -j ACCEPT -p tcp --dport 443
# Adding these for the HP Systems Management webpage (DISABLED 20160817)
#sudo iptables -A INPUT -j ACCEPT -p tcp --dport 2301
#sudo iptables -A INPUT -j ACCEPT -p tcp --dport 2381
# This one is for Webmin
sudo iptables -A INPUT -j ACCEPT -p tcp --dport 11111
#sudo iptables -A INPUT -j ACCEPT -p udp --dport 11111
#sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.199.1.12  --dport 1:65535
#sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.5.5.222  --dport 1:65535
#sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.64.101.96  --dport 3306
#  IPTABLES rule for MySQL access from Rapid7 Nexpose Scanner for DB Exports
#sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.3.120.35 --dport 3306
#sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.64.80.0/24  --dport 3306
#sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.1.205.0/24  --dport 3306
# rules for Nessus
#sudo iptables -A INPUT -j ACCEPT -p tcp --dport 21
#sudo iptables -A INPUT -j ACCEPT -p tcp --dport 23
# Nessus rule to allow only from 10.1.3.69
#sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.199.0.0/16  --dport 1241
sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.1.101.88/32  --dport 1:65535
sudo iptables -A INPUT -j ACCEPT -p udp -s 10.1.101.88/32  --dport 1:65535
#sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.1.3.69/32 --dport 1241
# Allow anything from these servers, to test SMB
sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.1.96.16/32 -d 0/0 --dport 1:65535
sudo iptables -A INPUT -j ACCEPT -p udp -s 10.1.96.62/32 -d 0/0 --dport 1:65535
sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.32.96.62/32 -d 0/0 --dport 1:65535
sudo iptables -A INPUT -j ACCEPT -p udp -s 10.32.96.62/32 -d 0/0 --dport 1:65535
sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.160.96.6/32 -d 0/0 --dport 1:65535
sudo iptables -A INPUT -j ACCEPT -p udp -s 10.160.96.6/32 -d 0/0 --dport 1:65535

sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.32.101.26/32 -d 0/0 --dport 1:65535
sudo iptables -A INPUT -j ACCEPT -p udp -s 10.32.101.26/32 -d 0/0 --dport 1:65535

sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.64.101.170/32 -d 0/0 --dport 1:65535
sudo iptables -A INPUT -j ACCEPT -p udp -s 10.64.101.170/32 -d 0/0 --dport 1:65535
sudo iptables -A INPUT -j ACCEPT -p tcp -s 127.0.0.1/32 -d 0/0 --dport 1:65535
sudo iptables -A INPUT -j ACCEPT -p udp -s 127.0.0.1/32 -d 0/0 --dport 1:65535
sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.1.101.45/32 -d 0/0 --dport 1:65535
sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.1.101.22/32 -d 0/0 --dport 1:65535
sudo iptables -A INPUT -j ACCEPT -p udp -s 10.1.101.22/32 -d 0/0 --dport 1:65535
# LET SolarWinds Access All
sudo iptables -A INPUT -j ACCEPT -p tcp -s 10.3.101.25/32 -d 0/0 --dport 1:65535
sudo iptables -A INPUT -j ACCEPT -p udp -s 10.3.101.25/32 -d 0/0 --dport 1:65535
sudo iptables -A INPUT -j ACCEPT -p icmp -s 10.3.101.25/32 -d 0/0 
sudo iptables -A INPUT -j ACCEPT -p icmp -s 10.64.97.16/32 -d 0/0 
sudo iptables -A INPUT -j ACCEPT -p icmp -s 10.58.101.228/32 -d 0/0 

#--------------------------------------------------

 # RPC mapper
 iptables -A INPUT -s 10.1.101.88/32 -p udp --dport 135 -j ACCEPT
 # NetBIOS Name Service (nbname)/Datagram Service (nbdatagram)
 iptables -A INPUT -s 10.1.101.88/32 -p udp --dport 137:138 -j ACCEPT
 # NetBIOS Session Service (nbsession)
 iptables -A INPUT -s 10.1.101.88/32 -p tcp --dport 139 -j ACCEPT
 # TCP Connection - establish 3-way handshake
 iptables -A INPUT -s 10.1.101.88/32 -p tcp --dport 445 -j ACCEPT
 # Kerberos V5 communication <2K Packets
 iptables -A INPUT -p udp -m udp --dport 88 -j ACCEPT
 # Kerberos V5 communication >2K Packets 
 iptables -A INPUT -p tcp -m tcp --dport 88 -j ACCEPT
 # NTP communication, for Kerberose V5 tickets?
 iptables -A INPUT -s 10.1.101.88/32 -p udp --dport 123 -j ACCEPT
 iptables -A INPUT -s 10.72.18.66/32 -p tcp  -j ACCEPT
#--------------------------------------------------
# Since no one else is doing NTP right, I feel compelled to serve it
# to whomever wants a reliable time source
sudo iptables -A INPUT -j ACCEPT -p tcp --dport 123
sudo iptables -A INPUT -j ACCEPT -p udp --dport 123

# -------------CLEAN UP RULE----------------------
sudo iptables -P INPUT DROP
