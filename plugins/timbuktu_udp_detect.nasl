#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25953);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/02/15 02:47:03 $");

  script_name(english:"Timbuktu Detection (UDP)");
  script_summary(english:"Scans for Timbuktu via UDP");

  script_set_attribute(attribute:"synopsis", value:"A remote control service is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote service is the UDP port for Timbuktu, a remote control
software application for Windows and Mac OS X.");
  script_set_attribute(attribute:"see_also", value:"http://netopia.com/software/products/tb2/");
  script_set_attribute(attribute:"solution", value:
"Make sure the use of this software is done in accordance with your
corporate security policy.  If this service is unwanted or not needed,
disable it or filter incoming traffic to this port.  Otherwise make sure
to use strong passwords for authentication.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");

  exit(0);
}


include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


port = 407;
if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");
if (known_service(port:port, ipproto:"udp")) exit(0);


soc = open_sock_udp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "UDP");


# Scan for Timbuktu installs.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

req = mkword(0x25) +
  mkword(0x22) +
  mkword(0xff01) +
  mkword(0x64) +
  mkword(0x307) +
  mkword(0x05) +
  mkword(0x02) +
  mkword(0x00);
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);


# If...
if (
  # the response is long-enough and...
  strlen(res) >= 4 &&
  # the packet looks right
  substr(res, 0, 3) == raw_string(0x00, 0x25, 0xd0, 0xb9)
)
{
  # Extract some interesting info for the report.
  info = "";
  # - server name.
  ofs = getword(blob:res, pos:0);
  if (ofs < strlen(res))
  {
    len = getword(blob:res, pos:ofs);
    name = substr(res, ofs+2, ofs+2+len-1);
    if (strlen(name))
    {
      info += "  Server name : " + name + '\n';
    }
  }

  # Register and report the service.
  register_service(port:port, ipproto:"udp", proto:"timbuktu");

  if (info)
  {
    report = string(
      "\n",
      "Nessus was able to gather the following information from the remote\n",
      "Timbuktu service :\n",
      "\n",
      info
    );
    security_note(port:port, proto:"udp", extra:report);
  }
  else security_note(port:port, proto:"udp");
}
