#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10288);
 script_version ("$Revision: 1.23 $");
 script_cvs_date("$Date: 2013/01/25 01:19:11 $");

 script_cve_id("CVE-2000-0138");
 script_osvdb_id(295);
 
 script_name(english: "Trin00 Trojan Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has been compromised." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Trin00, a Trojan Horse that can be
used to control your system or make it attack another network (this is 
actually called a Distributed Denial Of Service attack tool).

It is very likely that this host has been compromised." );
 script_set_attribute(attribute:"solution", value:
"Restore your system from backups, contact CERT and your local 
authorities." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/02/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/02/09");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Detects the presence of trin00");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2013 Tenable Network Security, Inc.");
 script_family(english: "Backdoors");
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

#
# The script code starts here
#

include('global_settings.inc');
if ( TARGET_IS_IPV6 ) exit(0);

if ( islocalhost() ) exit(0);
if ( ! thorough_tests ) exit(0);

command = string("png l44adsl");
pong = string("PONG");

ip  = forge_ip_packet(ip_hl:5, ip_v:4,   ip_off:0,
                     ip_id:9, ip_tos:0, ip_p : IPPROTO_UDP,
                     ip_len : 20, ip_src : this_host(),
                     ip_ttl : 255);
		   
length = 8 + strlen(command);		     
udpip = forge_udp_packet(ip : ip,
		         uh_sport : 1024,    
                         uh_dport : 27444,
			 uh_ulen : length,
			 data : command);
			 
			
trg = get_host_ip();
me  = this_host();
pf = string("udp and src host ", trg, " and dst host ", me, " and dst port 31335");
rep = send_packet(udpip, pcap_filter:pf, pcap_active:TRUE);			 	
if(rep)
{
  dstport = get_udp_element(udp:rep, element:"uh_dport");
  if(dstport == 31335)
  { 
   security_hole(port:27444, protocol:"udp");
  }
}
