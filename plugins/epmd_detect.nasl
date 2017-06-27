#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62351);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/09/27 16:08:14 $");

  script_name(english:"Erlang Port Mapper Daemon Detection");
  script_summary(english:"Detects an EPMD server");

  script_set_attribute(attribute:"synopsis", value:
"A port mapping service is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Erlang Port Mapper Daemon, which acts as a
name server on all hosts involved in distributed Erlang computations.");
  script_set_attribute(attribute:"see_also", value:"http://www.erlang.org/doc/man/epmd.html");
  script_set_attribute(attribute:"see_also", value:"http://www.erlang.org/doc/apps/erts/erl_dist_protocol.html");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:erlang:epmd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 4369);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

app = "Erlang Port Mapper Daemon";

if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery"))
{
  port = get_unknown_svc(port);
  if (!port) audit(AUDIT_SVC_KNOWN);
}
else
{
  port = 4369;
}

if (known_service(port:port)) exit(0, "The service listening on port " + port + " is already known.");

if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

# All parameters are big-endian.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

# Construct a NAMES_REQ.
req = mkword(1) + mkbyte(110);

# Send the NAMES_REQ, and get a NAMES_RESP.
send(socket:soc, data:req);
res = recv(socket:soc, min:4, length:1024);
close(soc);

# Confirm that we got a NAMES_RESP.
if (getdword(blob:res) != port)
  audit(AUDIT_NOT_LISTEN, app, port);

# Extract all the services from the response.
svcs = make_array();
res = substr(res, 4);
lines = split(res, sep:'\n', keep:FALSE);

foreach line (lines)
{
  matches = eregmatch(string:line, pattern:"name ([^ ]+) at port (\d+)");
  if (isnull(matches))
    continue;

  svcs[matches[1]] = matches[2];

  # Store the list of services.
  set_kb_item(name:"epmd/" + port + "/services", value:matches[1]);
  set_kb_item(name:"epmd/" + port + "/services/" + matches[1], value:matches[2]);
}

# Register the service.
register_service(port:port, ipproto:"tcp", proto:"epmd");

# Report our findings.
report = NULL;
if (report_verbosity > 0 && max_index(keys(svcs)) > 0)
{
  report =
    '\nThe following services were returned by our request :' +
    '\n';

  foreach name (sort(keys(svcs)))
  {
    report += '\n  ' + name + ' (' + svcs[name] + '/tcp)';
  }

  report += '\n';
}

security_note(port:port, extra:report);
