#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) 
{

  script_id(47605);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2011/03/11 21:18:08 $");

  script_name(english:"D-link Click 'n Connect Daemon Detection");
  script_summary(english:"Detects D-link Click 'n Connect Daemon"); 
 
  script_set_attribute(
    attribute:"synopsis",
    value:"A remote networking service is listening on the remote host."
  );
  script_set_attribute(
    attribute:"description", 
    value:

"The remote service is the D-link Click 'n Connect Daemon (DCCD), a
remote networking service provided on some D-link networking devices
that allows a remote client to view and configure the D-link device."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.dlink.com"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Limit incoming traffic to this port if desired."
  );
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/06");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  exit(0);

}

include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

port = 2003;
if (known_service(port:port, ipproto:"udp")) exit(0, "The service listening on UDP port "+port+" is already known.");
if (!get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open."); 

soc = open_sock_udp(port);
if (!soc) exit(1, "Failed to open a socket on UDP port "+port+"."); 


# 00 00 00 00 00 00 00 0a
dccd_detect_req  = mkbyte(0x00) + mkbyte(0x00) + mkbyte(0x00) + mkbyte(0x00) + mkbyte(0x00) + mkbyte(0x00) + mkbyte(0x00) + mkbyte(0x0a);

# 00 00 f5 ff 00 00 01 0a
dccd_detect_recv = mkbyte(0x00) + mkbyte(0x00) + mkbyte(0xf5) + mkbyte(0xff) + mkbyte(0x00) + mkbyte(0x00) + mkbyte(0x01) + mkbyte(0x0a);

# we send 'dccd_detect_req', we expect to receive 'dccd_detect_recv'
send(socket:soc, data:dccd_detect_req);

detect_data = recv(socket:soc, length:1024, min:128);
if (strlen(detect_data) == 0) exit(0, "The service listening on UDP port "+port+" did not respond.");

if (dccd_detect_recv >< detect_data)
{
  register_service(port:port, ipproto:"udp", proto:"dlink_dccd");
  security_note(port:port, proto:"udp");
}
else exit(0, "D-link DCCD service was not detected.");
