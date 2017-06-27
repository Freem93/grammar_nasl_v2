#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56822);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/11/15 19:17:23 $");

  script_name(english:"OpenVAS Manager / Administrator Detection");
  script_summary(english:"Detects an OpenVAS Manager or Administrator");

 script_set_attribute(attribute:"synopsis", value:
"An OpenVAS service is listening on the remote port.");
 script_set_attribute(attribute:"description", value:
"An OpenVAS Manager or OpenVAS Administrator daemon is listening on the
remote port.  These are the components of OpenVAS that control the
scanner and schedule tasks.");
  script_set_attribute(attribute:"solution", value: "Disable this service if you do not use it.");
  script_set_attribute(attribute:"see_also", value:"http://www.openvas.org/");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/02");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 9390, 9393);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

function do_check(port)
{
  local_var s, response;
  if (silent_service(port) || known_service(port:port) || !get_tcp_port_state(port)) 
    audit(AUDIT_NOT_LISTEN, "OpenVAS Administrator / Manager", port);
  
  s = open_sock_tcp(port);
  if (!s) 
    audit(AUDIT_SOCK_FAIL, port);

  send(socket:s, data:'<authenticate><credentials><username>sally</username><password>secret</password></credentials></authenticate>');
  response = recv(socket:s, length:1024, min:21);
  close(s);

  if (!response) 
    audit(AUDIT_RESP_NOT, port, "an authenticate request");
  
  if ("authenticate_response" >< response)
  {
    register_service(port:port, ipproto:"tcp", proto:"openvasmd");
    security_note(port);
    exit(0);
  }
  audit(AUDIT_NOT_DETECT, "OpenVAS Administrator / Manager", port);
}

if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  ports = add_port_in_list(list:get_kb_list("Services/unknown"), port:9390); # default port for OpenVAS Manager
  ports = add_port_in_list(list:ports, port:9393); # default port for OpenVAS Administrator
}
else ports = make_list(9390, 9393);

port = branch(ports);

do_check(port:port);
