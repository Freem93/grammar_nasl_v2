# 
# (C) Tenable Network Security, Inc.
#

# References:
# RFC 792 Internet Control Message Protocol
# RFC 791 Internet Protocol
#


include("compat.inc");

if(description)
{
 script_id(12264);
 script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2011/03/21 01:21:16 $");
 
 script_name(english:"Record Route");
 
 script_set_attribute(attribute:"synopsis", value:
"Record route" );
 script_set_attribute(attribute:"description", value:
"It is possible to obtain the traceroute to the remote host by 
sending packets with the 'Record Route' option set.  It is a complement to traceroute." );
 script_set_attribute(attribute:"solution", value:
"N/A" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/06/09");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Ping target with Record Route option");
 # script_category(ACT_GATHER_INFO);
 # See bugtraq ID # 10653
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english: "General");
 exit(0);
}

#
include("misc_func.inc");
include("global_settings.inc");
###include("dump.inc");

if (islocalhost()) exit(0); # Don't test the loopback interface
if ( TARGET_IS_IPV6 ) exit(0);

srcaddr = this_host();
dstaddr = get_host_ip();
n = 3;	# Number of tries

function report(packet, proto)
{
 local_var	rep, ihl, p, i, j, route, v, n, not_triv, ipaddr;

 if ( ! packet ) return 0;

 rep = strcat('Here is the route recorded between ', srcaddr, 
	' and ', dstaddr, ' :\n');

 ihl = (ord(packet[0]) & 0xF) * 4;
 ##display("IHL=", ihl, "\n");
 # No need to associate this piece of information with a specific port
###dump(ddata: packet, dtitle: "packet");
 p = ord(packet[22]) + 20;
 if (p > ihl) p = ihl;

 not_triv = 0; n = 0;
 for (i = 24; i < p; i += 4)
 {
  ipaddr = ord(packet[i-1]);
  for (j = 0; j < 3; j ++)
   ipaddr = strcat(ipaddr, '.', ord(packet[i+j]));
##display('>> ', ipaddr, '\n');
  route = strcat(route, ipaddr, '\n');
  if (ipaddr != srcaddr && ipaddr != dstaddr) not_triv = 1;
  n ++;
 }
##display('n=', n, ' not_triv=', not_triv, '\n');
 if (report_verbosity > 1 || n > 2 || not_triv)
  security_note(port: 0, protocol: proto, extra: rep + route);
}

# Currently, insert_ip_options() is buggy
rr = raw_string(	7,	# RR
			3+36,	# Length
			4,	# Pointer
			0)	# Padding
 + crap(length: 36, data: raw_string(0));

####
# Standard ping -R would do that:
# a = split(srcaddr, sep: '.', keep: 0);
# rr = raw_string(	7,	# RR
# 			3+36,	# Length
# 			8,	# Pointer
# 			int(a[0]),
# 			int(a[1]),
# 			int(a[2]),
# 			int(a[3]),
# 			0)	# Padding
#  + crap(length: 32, data: raw_string(0));
####

# We cannot use icmp_seq to identifies the datagrams because 
# forge_icmp_packet() is buggy. So we use the data instead

filter = strcat("icmp and icmp[0]=0 and src ", dstaddr, " and dst ", srcaddr);
seq = 0;

d = rand_str(length: 8);
for (i = 0; i < 8; i ++)
  filter = strcat(filter, " and icmp[", i+8, "]=", ord(d[i]));

ip = forge_ip_packet(ip_hl: 15, ip_v: 4, ip_tos: 0, ip_id: rand() % 65536,
	ip_off: 0, ip_ttl : 0x40, ip_p: IPPROTO_ICMP, ip_src : srcaddr, 
	data: rr, ip_len: 38+36);
icmp = forge_icmp_packet(ip: ip, icmp_type:8, icmp_code:0, icmp_seq: seq, 
	icmp_id: rand() % 65536, data: d);
r = NULL;
for (i = 0; i < n && ! r; i ++)
  r = send_packet(icmp, pcap_active: TRUE, pcap_filter: filter);
if (i < n) report(packet: r, proto: "icmp");
