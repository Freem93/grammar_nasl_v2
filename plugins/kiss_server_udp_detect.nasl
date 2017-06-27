#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31465);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2011/05/24 20:37:08 $");

  script_name(english:"KiSS PC-Link Server Detection (UDP)");
  script_summary(english:"Sends an ARE_YOU_KISS_PCLINK_SERVER request");

 script_set_attribute(attribute:"synopsis", value:
"A multimedia streaming service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is a PC-Link Server, used for streaming videos,
music, and pictures to a KiSS player, and this port is used by a
player when searching for a PC-Link server." );
 script_set_attribute(attribute:"see_also", value:"http://kissdx.vidartysse.net/" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67272d9e" );
 script_set_attribute(attribute:"solution", value:
"Make sure use of this software is in accordance with your corporate
security policy.  If this service is unwanted or not needed, disable
it or filter incoming traffic to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/03/14");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  exit(0);
}



include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


port = 8000;
if (known_service(port:port, ipproto:"udp")) exit(0);
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (!soc) exit(0);


# Search for a PC-Link server.
req = "ARE_YOU_KISS_PCLINK_SERVER?";
send(socket:soc, data:req);

res = recv(socket:soc, length:255);
if (strlen(res) == 0) exit(0);


# If...
if (
  # we're paranoid or...
  report_paranoia > 1 ||
  # it looks like a PC-Link server
  (
    # kissdx
    " - kissdx " >< res ||
    # LKS
    strlen(res) == 100
  )
)
{
  # Register and report the service.
  register_service(port:port, ipproto:"udp", proto:"kiss_server");

  sig = res - strstr(res, mkbyte(0));
  if (strlen(sig) == 0) sig = NULL;
  else set_kb_item(name:"KiSS/PCLink/"+port+"/Signature", value:sig);

  if (sig && report_verbosity)
  {
    report = string(
      "\n",
      "Here is the remote host's server signature :\n",
      "\n",
      "  ", sig, "\n"
    );
    security_note(port:port, proto:"udp", extra:report);
  }
  else security_note(port:port, proto:"udp");
}
