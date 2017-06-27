#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47135);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2011/03/17 17:53:54 $");

  script_name(english:"eyeMax DVR Server Detection");
  script_summary(english:"Sends an initial connection request");

  script_set_attribute(attribute:"synopsis", value:
"A network camera is connected on the remote host." );
  script_set_attribute(attribute:"description", value:
"eyeMax DVR Server is running on this port.  This service controls
network cameras, typically for a CCTV network." );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/25");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 9091);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") )
{
  port = get_unknown_svc(9091);
  if (!port) exit(0, "There are no unknown services.");
  if (silent_service(port)) exit(0, "The service listening on port "+port+" is silent.");
}
else port = 9091;

if (known_service(port:port)) exit(0, "The service listening on port "+port+" is already known.");

if (!get_tcp_port_state(port)) exit(0, "Port "+port+" is not open.");

v = get_unknown_banner2(port: port, dontfetch: 1);
if (isnull(v))
  exit(0, "The service listening port "+port+" does not have a banner.");

if (v[0] != '\x00\x00\x01\x00\x00\x00\x00\x00')
  exit(0, "The banner associated with the service listening on port "+port+" is not from eyeMax.");

if (report_paranoia < 1 && v[1] != 'spontaneous')
  exit(0, "The banner associated with the service listening on port "+port+" is not spontaneous.");

register_service(port:port, proto:"eyeMax-srv");
security_note(port);
