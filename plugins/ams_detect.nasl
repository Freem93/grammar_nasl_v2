#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25336);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/02/15 02:47:02 $");

  script_name(english:"avast! Management Server Detection");
  script_summary(english:"Sends a broadcast packet to detect AMS");

  script_set_attribute(attribute:"synopsis", value:"A network management service is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote service appears to be a broadcast listener for avast!
Management Server (AMS), which is used by avast! Distributed Network
Manager (ADNM) as well as avast! Managed Clients for remote deployment
and management of avast! antivirus within an enterprise.");
  script_set_attribute(attribute:"see_also", value:"http://www.avast.com/eng/adnm.html");
  script_set_attribute(attribute:"see_also", value:"http://files.avast.com/files/eng/adnmag.pdf");
  script_set_attribute(attribute:"solution", value:"Limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");

port = 6000;
if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

soc = open_sock_udp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "UDP");


# Send a request to detect a server.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

myip = split(this_host(), sep:".", keep:FALSE);
req =
  mkbyte(int(myip[0])) +
    mkbyte(int(myip[1])) +
    mkbyte(int(myip[2])) +
    mkbyte(int(myip[3])) +
  raw_string(
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x07, 0x00, 0x04, 0x00, 0x00, 0x00, 0xec, 0x03,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xa0, 0x62, 0x19, 0x00, 0x18, 0x00, 0x00, 0x00,
    0x2c, 0x5b, 0x00, 0xf6, 0x20, 0x00, 0x00, 0x00,
    0xa0, 0xfb, 0x00, 0x02
  );
req =
  mkdword(1) +
  mkdword(12+strlen(req)) +
  mkdword(0) +
  req;
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);


# If the response looks right..
if (
  strlen(res) > 8 &&
  getdword(blob:res, pos:0) == 1 &&
  getdword(blob:res, pos:4) == strlen(res) &&
  getdword(blob:res, pos:8) == 2
)
{
  # Register and report the service.
  register_service(port:port, ipproto:"udp", proto:"ams_broadcast");

  info = NULL;
  if (strlen(res) >= 0x21)
  {
    ver =
      getword(blob:res, pos:0x1a) + "." +
      getword(blob:res, pos:0x18) + "." +
      getword(blob:res, pos:0x1e);
    if (ver =~ "^[0-9]")
    {
      set_kb_item(name:"ADNM/Version", value:ver);
      info += '  ADMN version      : ' + ver + '\n';
    }

    # nb: not sure why, but this is big-endian.
    agent_port = (getbyte(blob:res, pos:0x20) << 8) +
                 getbyte(blob:res, pos:0x21);
    if (agent_port > 0 && agent_port <= 65335)
      info += '  Remote agent port : ' + agent_port + '\n';
  }

  if (info)
  {
    report = string(
      "\n",
      info
    );
   security_note(port:port, proto:"udp", extra:report);
  }
  else security_note(port:port, proto:"udp");
}
