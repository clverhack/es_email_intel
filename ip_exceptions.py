import ipaddress
import re

def checkIPexceptions(ip):
	ip = unicode(ip)
	if re.search('^0\d', ip): return 1
	if str(ip) == '0.0.0.0': return 1
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'1.2.3.1/32'): return 1 # Sample address
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'1.3.1.2/32'): return 1 # Sample address
	
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'2.6.39.3/32'): return 1 # Linux kernel version

	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'8.8.4.0/24'): return 1 # The Goog
	
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'199.200.24.181/32'): return 1 # Work.
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'1.2.3.4/32'): return 1 # BS
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'8.8.8.8/32'): return 1 # Goog
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'4.2.2.2/32'): return 1 # Goog
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'216.106.102.33/32'): return 1 # Yours truly
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'127.0.0.1/32'): return 1 # kcabpool
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'192.168.0.0/16'): return 1 # RFC1918
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'10.0.0.0/8'): return 1 # RFC1918
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'172.16.0.0/12'): return 1 # RFC1918
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'1.0.1.0/24'): return 1 # BS
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'67.231.144.0/20'): return 1 # Proofpoint
	
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'224.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'225.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'226.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'227.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'228.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'229.0.0.0/8'): return 1 # Reserved addresses
	
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'230.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'231.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'232.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'233.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'234.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'235.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'236.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'237.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'238.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'239.0.0.0/8'): return 1 # Reserved addresses
	
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'240.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'241.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'242.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'243.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'244.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'245.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'246.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'247.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'248.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'249.0.0.0/8'): return 1 # Reserved addresses
	
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'250.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'251.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'252.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'253.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'254.0.0.0/8'): return 1 # Reserved addresses
	if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(u'255.0.0.0/8'): return 1 # Reserved addresses
	return 0