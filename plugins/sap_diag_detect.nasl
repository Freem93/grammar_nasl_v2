#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56981);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2011/12/01 00:44:38 $");

  script_name(english:"SAP Dynamic Information and Action Gateway Detection");
  script_summary(english:"Detects an SAP DIAG server.");

  script_set_attribute(attribute:"synopsis", value:
"A SAP DIAG server is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a SAP DIAG server, which is used to
communicate with SAP GUI clients.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4caa78c5");

  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/30");

  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:sap:diag");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 3200);

  exit(0);
}

include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

# Packet bodies.
PING = raw_string("NI_PING", 0x00);
PONG = raw_string("NI_PONG", 0x00);

if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery"))
{
  port = get_unknown_svc(3200);
  if (!port) exit(0, "There are no unknown services.");
}
else port = 3200;

# Check the state of the target port.
if (known_service(port:port)) exit(0, "The service is already known on port " + port + ".");

if (!get_tcp_port_state(port)) exit(0, "Port " + port + " is not open.");

# Try to connect to the server.
soc = open_sock_tcp(port);
if (!soc) exit(1, "Failed to open a socket on port " + port + ".");

# All parameters are big-endian.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

# Put the request together.
req = mkdword(strlen(PING)) + PING;

# Probe the service.
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);

# Check the response's format.
if (strlen(res) == 0) exit(0, "The service on port " + port + " failed to respond.");

if (strlen(res) < 4) exit(0, "The response from the service on port " + port + " is too short.");

# Parse the response.
len = getdword(blob:res, pos:0);
if (len != strlen(PONG)) exit(0, "The response from the service on port " + port + " has a length that doesn't match a pong.");

body = substr(res, 4);
if (body != PONG) exit(0, "The response from the service on port " + port + " isn't pong.");

# Record the implied system number of any instances we've found.
sysnr = port - 3200;

set_kb_item(name:"SAP/SYSNR", value:sysnr);
set_kb_item(name:"SAP/SYSNR/" + sysnr + "/DIAG", value:port);

# Register the service.
register_service(port:port, ipproto:"tcp", proto:"sap_diag");

# Report our findings.
if (report_verbosity > 0)
{
  body = str_replace(find:raw_string(0), replace:"", string:body);

  report =
    '\nWhen a ping was sent over the SAP DIAG protocol, the remote service' +
    '\nresponded with :' +
    '\n' +
    '\n  ' + body +
    '\n';

  security_note(port:port, extra:report);
}
else security_note(port);
