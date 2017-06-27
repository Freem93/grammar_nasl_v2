#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29930);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2012/10/16 22:09:59 $");

  script_name(english:"netOctopus Agent Detection (UDP)");
  script_summary(english:"Searches for an agent via UDP");

  script_set_attribute(attribute:"synopsis", value:
"An asset management agent is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote service is a netOctopus Agent, the agent piece of the netOctopus
asset management software suite installed on individual computers.");
  script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:motorola:netoctopus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2012 Tenable Network Security, Inc.");

  exit(0);
}



include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


port = 1917;
if (known_service(port:port, ipproto:"udp")) exit(0);
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (!soc) exit(0);


# Search for the agent.
req = 
  "LooS" +
  mkword(0) +
  mkword(1) +
  "nOAg" +
  crap(data:mkbyte(0), length:0x2c);
send(socket:soc, data:req);
res = recv(socket:soc, length:1024, min:4);


# If...
if (
  # the response is long-enough and...
  strlen(res) >= 0x45 &&
  # it looks right.
  "LooR" == substr(res, 0, 3) &&
  "nOAg" >< res
)
{
  # Extract some interesting info.
  info = "";
  # - computer name.
  len = getbyte(blob:res, pos:8);
  info += '  netOctopus Computer Name       : ' + substr(res, 9, 9+len-1) + '\n';
  # - serial number.
  serial = hexstr(substr(res, 0x32, 0x35)) + '-' +
           hexstr(substr(res, 0x36, 0x37)) + '-' +
           hexstr(substr(res, 0x38, 0x39)) + '-' +
           hexstr(substr(res, 0x3a, 0x3b)) + '-' +
           hexstr(substr(res, 0x3c, 0x42));
  serial = toupper(serial);
  info += '  netOctopus Agent Serial Number : ' + serial + '\n';
  # - version.
  ver = getbyte(blob:res, pos:0x42) + '.' +
        (getbyte(blob:res, pos:0x43) >> 4) + '.' +
        (getbyte(blob:res, pos:0x43) & 0x0f);
  info += '  netOctopus Agent Version       : ' + ver + '\n';

  # Register and report the service.
  register_service(port:port, ipproto:"udp", proto:"netoctopus_agent");

  set_kb_item(name:"netOctopus/Agent/udp/"+port+"/Version", value:ver);

  if (report_verbosity)
  {
    report = string(
      "\n",
      "Here is some information about the remote netOctopus Agent :\n",
      "\n",
      info
    );
    security_note(port:port, proto:"udp", extra:report);
  }
  else security_note(port:port, proto:"udp");
}
