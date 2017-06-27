#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62349);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/09/27 16:08:14 $");

  script_name(english:"Advanced Message Queuing Protocol Detection");
  script_summary(english:"Detects an AMQP server");

  script_set_attribute(attribute:"synopsis", value:
"A messaging service is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running an AMQP server, which provides messaging and
queuing services for other applications.");
  script_set_attribute(attribute:"see_also", value:"http://www.amqp.org/");
  script_set_attribute(attribute:"see_also", value:"http://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf");
  # http://docs.oasis-open.org/amqp/core/v1.0/cos01/amqp-core-complete-v1.0-cos01.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?388dd79c");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/amqp", 5671, 5672);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

app = "Advanced Message Queuing Protocol";

# Get the ports that AMQP has been found on.
port = get_service(svc:"amqp", default:5672, exit_on_fail:TRUE);

# Connect to the port.
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

# All parameters are big-endian.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

# Construct a request with a version of 0.0.0.
magic = "AMQP";
req = raw_string(
  magic, # Magic cookie
  0,     # Protocol ID
  0,     # Major version number
  0,     # Minor version number
  0      # Revision number
);

# Send the request and hope for an AMQP response.
send(socket:soc, data:req);
res = recv(socket:soc, min:8, length:128);
close(soc);

# Confirm that we're talking to an AMQP server.
if (isnull(res) || strlen(res) != 8 || substr(res, 0, 3) != magic)
  audit(AUDIT_NOT_LISTEN, app, port);

# Check if the server requires authentication or encryption.
proto = getbyte(blob:res, pos:4);
kb = "amqp/" + port + "/";
set_kb_item(name:kb + "protocol/id", value:proto);

# We gave a bogus version, so it should tell us its version.
ver_maj = getbyte(blob:res, pos:5);
ver_min = getbyte(blob:res, pos:6);
ver_rev = getbyte(blob:res, pos:7);
ver = join(ver_maj, ver_min, ver_rev, sep:".");
set_kb_item(name:kb + "protocol/version", value:ver);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  # Translate protocol ID.
  if (proto == 0)
    type = "Basic";
  else if (proto == 2)
    type = "StartTLS";
  else if (proto == 3)
    type = "SASL";
  else
    type = "Unrecognized";
  type += " (" + proto + ")";

  report =
    '\nAn AMQP server with the following characteristics was found :' +
    '\n' +
    '\n  Protocol : ' + type +
    '\n  Version  : ' + ver +
    '\n';
}

security_note(port:port, extra:report);
