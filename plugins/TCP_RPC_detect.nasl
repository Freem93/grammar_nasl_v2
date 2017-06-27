#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53333);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/02/19 21:50:16 $");

  script_name(english:"Detect RPC over TCP");
  script_summary(english:"Call RPC #0 on all open TCP ports");

  script_set_attribute(attribute:"synopsis", value:"An RPC service is running on this port.");
  script_set_attribute(attribute:"description", value:
"This service answered to a RPC procedure #0 call.

For whatever reason, it was not registered by the portmapper or Nessus
could not query to the portmapper (e.g.  if port 111 is filtered or not
scanned).");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"RPC");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_keys("Services/unknown");
  script_exclude_keys("global_settings/disable_service_discovery", "rpc/portmap");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("sunrpc_func.inc");

if (!thorough_tests) audit(AUDIT_THOROUGH);

if (get_kb_item("global_settings/disable_service_discovery")) exit(0, "Service discovery is disabled.");

port = get_unknown_svc();
if (!port) audit(AUDIT_SVC_KNOWN);

if (silent_service(port)) exit(0, "Port " + port + " is a silent service, so it is ignored.");

if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SVC_FAIL, "the unknown", port);

# Generate an RPC request using dummy (all zero) parameters.
req = rpc_packet(prog:0, vers:2, proc:0, udp:FALSE);

# Send the RPC request and receive a response.
res = rpc_sendrecv(socket:soc, packet:req, udp:FALSE);

# Clean up.
close(soc);

# If the service didn't respond, or the response couldn't be parsed,
# or if the status codes indicate that there wasn't an error response,
# we know nothing except that it's probably not an RPC service.
if (
  isnull(res) &&
  rpc_reply_stat() == RPC_REPLY_STAT_ACCEPTED &&
  rpc_accept_stat() == RPC_ACCEPT_STAT_SUCCESS
) audit(AUDIT_NOT_LISTEN, "An RPC service", port);

# We've gotten something back from the service that looks like a valid
# response, possibly indicating an error, so register the port as an
# RPC service.
register_service(port:port, proto:"rpc", ipproto:"tcp");
security_note(port);
