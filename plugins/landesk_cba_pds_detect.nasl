#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29993);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/12/19 23:04:05 $");

  script_name(english:"LANDesk Ping Discovery Service Detection");
  script_summary(english:"Pings an agent");

  script_set_attribute(attribute:"synopsis", value:
"An asset management agent is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote service is a Ping Discovery Service, one of the components
of LANDesk Management Suite installed on managed clients for
communicating with the administrative console.");
  # http://web.archive.org/web/20090503002610/http://www.landesk.com/SolutionServices/product.aspx?id=716
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae87ac86");
  script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/17");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");

  exit(0);
}



include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


port = 38293;
if (known_service(port:port, ipproto:"udp")) exit(0);
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (!soc) exit(0);


# Try to ping the agent.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

req = mkword(0x0a02) +
  mkword(0x10) +
  "PINGBDCV" +
  mkword(0) + mkword(0);
send(socket:soc, data:req);
res = recv(socket:soc, length:128);


# If the response looks right...
if (
  strlen(res) >= 12 &&
  stridx(res, "BDCVPING") == 4 &&
  getword(blob:res, pos:0x12)+4 <= strlen(res)
)
{
  # Extract some interesting info.
  info = "";
  # - OS info.
  if (strlen(res) > 0x18)
  {
    ver = getbyte(blob:res, pos:0x1b) + "." +
          getbyte(blob:res, pos:0x1a);
    build = getword(blob:res, pos:0x18);
    info += '  OS Version    : ' + ver + '\n';
    info += '  OS Build      : ' + build + '\n';
  }
  # - computer name
  i = 0x20;
  name = "";
  while (i < strlen(res))
  {
    c = getbyte(blob:res, pos:i);
    i += 2;
    if (c == 0) break;
    name += raw_string(c);
  }
  if (name) info += '  Computer Name : ' + name + '\n';
  # - MAC address.
  if (i+6 < strlen(res))
  {
    mac = hexstr(substr(res, i, i+5));
    mac= toupper(mac);
    info += '  MAC Address   : ' + mac + '\n';
  }
  # - device ID.
  if (i+6+16 < strlen(res))
  {
    id = hexstr(substr(res, i+6,  i+9)) + '-' +
         hexstr(substr(res, i+10, i+11)) + '-' +
         hexstr(substr(res, i+12, i+13)) + '-' +
         hexstr(substr(res, i+14, i+15)) + '-' +
         hexstr(substr(res, i+16, i+21));
    id = toupper(id);
    info += '  Device ID     : {' + id + '}\n';
  }

  # Register and report the service.
  register_service(port:port, ipproto:"udp", proto:"landesk_pds");

  if (report_verbosity)
  {
    report = string(
      "\n",
      "Here is some information collected from the remote LANDesk CBA Ping\n",
      "Discovery Service :\n",
      "\n",
      info
    );
    security_note(port:port, proto:"udp", extra:report);
  }
  else security_note(port:port, proto:"udp");
}
