#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10283);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2014/05/26 16:32:07 $");

 script_cve_id("CVE-2000-0138");
 script_osvdb_id(295);

 script_name(english:"TFN (Tribe Flood Network) Trojan Detection");
 script_summary(english:"Detects the presence of TFN");

 script_set_attribute(attribute:"synopsis", value:"The remote host has been compromised.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running TFN (Tribe Flood Network), which
is a Trojan Horse that can be used to control your system or make it
attack another network.

It is very likely that this host has been compromised");
 script_set_attribute(attribute:"solution", value:
"Restore your system from backups, contact CERT and your local
authorities.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/02/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/12/10");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");
 script_family(english:"Backdoors");

 script_require_keys("Settings/ParanoidReport");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if(islocalhost())exit(0);
if ( TARGET_IS_IPV6 ) exit(0);

ip = forge_ip_packet(ip_hl:5, ip_v:4,   ip_off:0,
                     ip_id:9, ip_tos:0, ip_p : IPPROTO_ICMP,
                     ip_len : 20, ip_src : this_host(),
                     ip_ttl : 255);

#
# We send the command ID_SYNPORT (678) and wait for
# ID_ACK (123)
#

ID_ACK = 123;
ID_SYNPORT = 678;
icmp = forge_icmp_packet(ip:ip,icmp_type : 8, icmp_code:0,
                          icmp_seq : 1, icmp_id : ID_SYNPORT,
			  data:"1234");

filter = string("icmp and src host ", get_host_ip(), " and dst host ", this_host());
r = send_packet(icmp, pcap_active:TRUE, pcap_filter:filter);
if(r)
{
 type = get_icmp_element(icmp:r, element:"icmp_id");
 if(type == ID_ACK)security_hole(protocol:"icmp",port:0);
}


