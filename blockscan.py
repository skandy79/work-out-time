#!/usr/local/ibin/python-sa

#Original script by David Lusby and modified by Scott Naylor with permission
#Changes made by Scott Naylor include expanded whois search terms to identify CN based ip ranges and expanded WP scan searches

import collections
import subprocess
import re

auto_block = ["CHINANET", "WENZHOU", "HANGZHOU", "wuxi-xuelang", "DINGQI", "ALISOFT", "HSOFT", "AQIDC", "BITNET", "CTTNET", "ZLNET", "MOVEINTERNET-NETWORK", "UNICOM", "WEST263", "NIBO-LANZHONG-LTD", "TUNET", "SUZHOU-CS", "CMNET", "MCCL-CHN", "NINGBO-ZHANGLI-CO", "WENCHENG-PRESS", "GUANGZHOU-ZS", "GZU-CN", "thjy-net", "sjhy-net", "jingangli1z", "SUZHOU-AOERSI", "HEETHAILIMITED-HK", "HEETHAI-HK"]
never_block = ["NTT", "OCN", "ARCSTAR", "VPS-TOKYO", "WWW-SERVICE"]
ip_whitelist = ["128.242.54.69","127.0.0.1"]

def get_auto(whois):
  auto = "N"
  for host in auto_block:
    if host in whois:
      auto = "Y"
      return auto

def get_never(whois):
  never = "N"
  for host in never_block:
    if host in whois:
      never = "Y"
      return never

def check_block(ip,port):
  ipfstat_cmd="ipfstat -h -i|grep " + ip + "|awk '{print $6,$11}'"
  ipfstat = subprocess.check_output(ipfstat_cmd, shell=True)
  ip_port = str(ip) + "/32 " + str(port)
  if ip_port in ipfstat:
    blocked = "Y"
    return blocked

def add_block(ip, port):
  block_cmd = "echo 'block in quick from " + str(ip) + "/32 to any port=" + str(port) + "' >> /etc/ipf.rules"
  block = subprocess.check_output(block_cmd, shell=True)
  ipf_cmd = "ipf -Fa -f /etc/ipf.rules"
  ipf = subprocess.check_output(ipf_cmd, shell=True)

def log_block(ip,port,whois):
   date_cmd = "date +'%m/%d/%y %H:%M'"
   date = subprocess.check_output(date_cmd, shell=True)
   date = date.rstrip()
   log_cmd = "echo '[" + date + "] " + str(ip) + ":" + str(port) + " [" + whois + "]' >> /var/log/blockscan.log" 
   log = subprocess.check_output(log_cmd, shell=True)

def block_prompt(port):
  answer = raw_input("Block port " + str(port) + "? [Y/N] ") 
  answer = answer.upper()
  return answer 

def block_ip(ip,port,whois):
        if check_block(ip,port) == "Y":
          print "Already blocked.\n"
        elif get_never(whois) == "Y":
          print "Skipping NTT/OCN IP address....\n"
        elif get_auto(whois) == "Y":
          print "Automatic block for [" + whois + "]....block in quick from " + str(ip) + "/32 to any port=" + str(port) + "\n"
          add_block(ip,port)
          log_block(ip,port,whois)
        else: 
          if block_prompt(port) == "Y":
            print "Adding...block in quick from " + str(ip) + "/32 to any port=" + str(port) + "\n"
            add_block(ip,port)
            log_block(ip,port,whois)
          else:
            print "\n"

def check_whitelist(line):
  whitelist = "N"
  for entry in ip_whitelist:
    if entry in line:
      whitelist = "Y"
      return whitelist 

def process_line(line):
  line = line.lstrip()                                                                                        
  line = line.split() 
  return (line) 

def get_whois(ip):
  whois_cmd = "whois " + ip + "|grep -i netname|tail -1|awk '{print $2}'"
  whois = subprocess.check_output(whois_cmd, shell=True)
  whois=whois.rstrip()
  if whois == "":
    whois_cmd = "whois " + ip + "|egrep -i 'verio|ntt|ocn'|tail -1|awk '{print $1, $2}'"
    whois = subprocess.check_output(whois_cmd, shell=True)
    whois=whois.rstrip("\n")
  if whois == "":
    whois_cmd = "whois " + ip + "|grep NET|tail -1|awk '{print $1, $2}'"
    whois = subprocess.check_output(whois_cmd, shell=True)
    whois=whois.rstrip("\n")
  if whois == "":
    return "No result!\n"
  else:
    return whois

def get_port(cmd):
  if "proftpd" in cmd:
    port=21
    return port
  elif "auth.log" in cmd:
    port=22
    return port
  elif "dovecot" in cmd:
    port=110
    return port
  elif "access_log" in cmd:
    port=80
    return port
  else:
    return "I don't know which port to block, moving on....\n"                                                 

def find_and_block(cmd):
  cmdoutput = subprocess.check_output(cmd, shell=True)
  for line in cmdoutput.split("\n"):
    if not re.search('[a-zA-Z]', line) and not re.search('^$', line):
      line = process_line(line)
      (num, ip) = line[0], line[1]
      if not ip in ip_whitelist:
        whois = get_whois(ip)
        print num + " entries from " + ip + " [" + whois + "]"
        port = get_port(cmd)
        block_ip(ip,port,whois)
      else:
        print ip + " is whitelisted!\n"

commands = (
  ('SSH scans', "tail -10000 /var/log/auth.log|grep Failed|awk '{print $11}'|sort|uniq -c|sort -rn|awk '$1 > 25 {print $0}'"),
  ('SSH connection attacks', "tail -10000 /var/log/auth.log|grep Connection|awk '{print $8}'|sort|uniq -c|sort -rn|awk '$1 > 50 {print $0}'"),
  ('FTP scans', "grep proftpd /var/log/auth.log|grep 'bad password'| awk '{print $7}' | cut -d[ -f2 | cut -d] -f1|sort|uniq -c|sort -rn|head|awk '$1 > 50 {print $0}'"),
  ('Dovecot scans', "cat /service/dovecot/log/main/current | grep failed | awk '{print $12}' | grep 'rip=' | cut -d= -f2 | cut -d, -f1| sort | uniq -c | sort -rn | awk '$1 > 50 {print $0}'"),
  ('wp-login.php scans', "grep -h wp-login.php /usr/home/*/www/logs/access_log|awk '{print $1}'|sort|uniq -c|sort -rn|awk '$1 > 500 {print $0}'"),
  ('xml-rpc.php scans', "grep -h xmlrpc.php /usr/home/*/www/logs/access_log|awk '{print $1}'|sort|uniq -c|sort -rn|awk '$1 > 500 {print $0}'"),
  ('wp-login.php scans in todays archive', "zcat /usr/home/*/www/logs/access_log.0.gz | grep -h wp-login.php | awk '{print $1}' | sort | uniq -c | sort -rn | awk '$1 > 500 {print $0}'"),
  ('xml-rpc.php scans in todays archive', "zcat /usr/home/*/www/logs/access_log.0.gz | grep -h xmlrpc.php | awk '{print $1}' | sort | uniq -c | sort -rn | awk '$1 > 500 {print $0}'"),
  ('joomla registration scans', "grep '/index.php/component/users/?view=registration' /usr/home/*/www/logs/access_log |awk '{print $1}'|sort|uniq -c|sort -rn|awk '$1 > 10 {print $0}'"),  
)

commands = collections.OrderedDict(commands)
n = 0

for key in commands:
  n = n + 1
  print "\n" + str(n) + ".)  Checking for " + key + "....\n--------------------------------------------------\n"
  cmd = commands[key] 
  find_and_block(cmd)
