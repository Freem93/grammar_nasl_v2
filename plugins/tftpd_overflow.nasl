#
# (C) Tenable Network Security, Inc.
#

# Not tested against a vulnerable server!

include("compat.inc");

if (description)
{
 script_id(18264);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2016/11/23 20:42:24 $");

 # Not sure for 10526 or 11584
 # BID=6043 / CVE-2002-1542 is different
 script_cve_id("CVE-2002-0813", "CVE-2003-0380");
 script_bugtraq_id(401, 5328, 7819);
 script_osvdb_id(854, 4343);

 script_name(english:"TFTPD Server Filename Handling Remote Overflow");
 script_summary(english:"Crashes TFTPD with a big UDP datagram");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a buffer
overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote TFTP server dies when it receives a too big UDP datagram.
An attacker may use this flaw to disable the server, or even execute
arbitrary code on the system.");
 script_set_attribute(attribute:"solution", value:"Upgrade software, or disable this service.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/07/25");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/16");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 # Not an ACT_DESTRUCTIVE_ATTACK (see CVE-2002-0813), should be an ACT_KILL_HOST
 # but sending 700+ packets is slow
 script_category(ACT_FLOOD);

 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");

 script_require_keys("Services/udp/tftp", "Settings/ParanoidReport");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("dump.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if ( TARGET_IS_IPV6 ) exit(0);

if(islocalhost()) exit(0);	# ?

# This function cannot yet send UDP packets bigger than the MTU
# TBD: write 'fragment_packet' function
function tftp_ping(port, huge)
{
 local_var	req, rep, sport, ip, u, filter, data, i;

 debug_print('tftp_ping: huge=', huge, '\n');

 if (huge)
  req = '\x00\x01'+crap(huge)+'\0netascii\0';
 else
  req = '\x00\x01Nessus'+rand()+'\0netascii\0';

 sport = rand() % 64512 + 1024;
 ip = forge_ip_packet(ip_hl : 5, ip_v: 4,  ip_tos:0,
	ip_len:20, ip_off:0, ip_ttl:64, ip_p:IPPROTO_UDP,
	ip_src: this_host());

 u = forge_udp_packet(ip:ip, uh_sport: sport, uh_dport:port, uh_ulen: 8 + strlen(req), data:req);

 filter = 'udp and dst port ' + sport + ' and src host ' + get_host_ip() + ' and udp[8:1]=0x00';

 data = NULL;
 for (i = 0; i < 2; i ++)	# Try twice
 {
  rep = send_packet(u, pcap_active:TRUE, pcap_filter:filter);
  if(rep)
  {
   if (debug_level > 2) dump(ddata: rep, dtitle: 'TFTP (IP)');
   data = get_udp_element(udp: rep, element:"data");
   if (debug_level > 1) dump(ddata: data, dtitle: 'TFTP (UDP)');
   if (data[0] == '\0' && (data[1] == '\x03' || data[1] == '\x05'))
   {
    debug_print('tftp_ping(port=', port, ',huge=', huge, ') succeeded\n');
    return TRUE;
   }
  }
 }
 debug_print('tftp_ping(port=', port, ',huge=', huge, ') failed\n');
 return FALSE;
}

#
port = get_kb_item('Services/udp/tftp');
if (! port) port = 69;
if (get_kb_item('tftp/'+port+'/backdoor')) exit(0);
if (! tftp_ping(port: port)) exit(0);

start_denial();

# 700 is good for CISCO, and more than enough for atftpd
# 1000 might be necessary WinAgents, but the flaw might be different
tftp_ping(port: port, huge: 1000);

# I'll check this first, in case the device reboots
tftpalive = tftp_ping(port: port);
alive = end_denial();

if (! alive)
 {
  report = string("\n\n",
    "The remote device freezes or reboots when a too big UDP datagram","\n",
    "is sent to the TFTP server.",
    "\n");
    security_hole(port: port, proto: "udp", extra:report);
  }
else
 if (! tftpalive)
  security_hole(port: port, proto: "udp");

if (! alive || ! tftpalive)
 set_kb_item(name: 'tftp/'+port+'/overflow', value: TRUE);
