#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56823);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2011/12/02 21:22:47 $");

  script_name(english:"OpenVAS Scanner Detection");
  script_summary(english:"Detects an OpenVAS scanner");

 script_set_attribute(attribute:"synopsis", value:
"An OpenVAS service is listening on the remote port.");

 script_set_attribute(attribute:"description", value:
"An OpenVAS Scanner daemon is listening on the remote port.  This is
the component of OpenVAS that performs security scans and / or
audits.");
  script_set_attribute(attribute:"solution", value: "Disable this service if you do not use it.");
  script_set_attribute(attribute:"see_also", value:"http://www.openvas.org/");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/02");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 9391);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(9391);
  if (!port) exit(0, "There are no unknown services.");
  if (silent_service(port)) exit(0, "The service listening on port "+port+" is silent.");
}
else port = 9391;
if (known_service(port:port)) exit(0, "The service is already known on port "+port+".");
if (get_port_transport(port) == ENCAPS_IP) exit(0, "The service listening on "+port+" does not encrypt traffic.");
if (!get_tcp_port_state(port)) exit(1, "Port "+port+" is not open.");

# Open the connection
s = open_sock_tcp(port);
if (!s) exit(1, "Can't open socket on port "+port+".");

send(socket:s, data:'< OTP/1.0 >\r\n');
response = recv(socket:s, length:1024, min:15);
if (strlen(response) == 0) exit(0, "The service listening on port "+port+" failed to respond.");

if ("< OTP/1.0 >" >< response && "User :" >< response)
{
  register_service(port:port, ipproto:"tcp", proto:"openvas");
  security_note(port);
  exit(0);
}
else exit(0, "The service listening on port "+port+" is not an OpenVAS Scanner.");

