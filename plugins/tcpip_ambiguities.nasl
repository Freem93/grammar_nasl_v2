#
# (C) Tenable Network Security, Inc.
#

# Ref:
# To: bugtraq@securityfocus.com
# From: security@sco.com
# Date: Mon, 5 May 2003 11:01:07 -0700
# Subject: Security Update: [CSSA-2003-019.0] OpenLinux: tcp SYN with FIN 
#          packets are not discarded


include("compat.inc");

if(description)
{
 script_id(11618);
 script_version ("$Revision: 1.26 $");
 script_bugtraq_id(7487);
 script_osvdb_id(2118);
 script_xref(name:"CERT", value:"464113");

 script_name(english:"TCP/IP SYN+FIN Packet Filtering Weakness");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to bypass firewall rules." );
 script_set_attribute(attribute:"description", value:
"The remote host does not discard TCP SYN packets that have
the FIN flag set.

Depending on the kind of firewall you are using, an attacker
may use this flaw to bypass its rules." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Oct/274" );
 script_set_attribute(attribute:"solution", value:
"Contact your vendor for a patch." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/10/18");
 script_cvs_date("$Date: 2016/11/03 20:40:06 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 
 script_summary(english:"Sends a SYN+FIN packet and expects a SYN+ACK");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Firewalls");
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#
# The script code starts here
#

# do not test this bug locally
include('global_settings.inc');

if ( TARGET_IS_IPV6 )
 exit(0, "This script works for IPv4 targets.");

if ( report_paranoia < 2 )
 exit(0, "This script only runs in 'paranoid' mode.");

if (islocalhost())exit(0, "localhost cannot be tested.");
if (islocalnet()) exit(0, "Targets on the local network cannot be tested.");

port = get_host_open_port();
if(!port) exit(1, "No TCP open port was found.");

ip = forge_ip_packet(ip_hl:5, ip_v:4,   ip_off:0,
                     ip_id:9, ip_tos:0, ip_p : IPPROTO_TCP,
                     ip_len : 20, ip_src : this_host(),
                     ip_ttl : 255);

sport = 1024 + rand() % 64512;
tcp = forge_tcp_packet(ip:ip, th_sport:sport, th_dport:port, 
		       th_win:4096,th_seq:rand(), th_ack:0,
		       th_off:5, th_flags:TH_SYN|TH_FIN, th_x2:0,th_urp:0);
		       
filter = string("tcp and src host ", get_host_ip(), " and dst host ",
this_host(), " and src port ", port, " and dst port ", sport);

for(i=0;i<3;i++)
{
 r = send_packet(tcp, pcap_active:TRUE, pcap_timeout:1, pcap_filter:filter);
 if(r)
 {
  hl = (ord(r[0]) & 0xF) * 4;
  tcp = substr(r, hl);
  if (strlen(tcp) > 13 && ord(tcp[13]) == 18)
   security_warning(0);
  exit(0);
 }
}

exit(0, "The target is not vulnerable");
