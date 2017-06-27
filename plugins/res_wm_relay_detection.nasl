#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70291);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/10/03 17:36:12 $");

  script_name(english:"RES Workspace Manager Relay Server Detection");
  script_summary(english:'Identifies RES Workspace Manager Relay servers.');

  script_set_attribute(attribute:"synopsis", value:
"A RES Workspace Manager Relay Server is running on this port.");
  script_set_attribute(attribute:"description", value:
"The remote service is a RES Workspace Manager Relay Server.  It
communicates with a central database of RES Workspace Manager, a
workspace virtualization platform, or another RES Workspace Manager
Relay Server and provides caching services to RES Workspace Manager
Agents and other RES Workspace Manager Relay Servers.  It is used to
reduce load on the RES Workspace Manager central database and improve
scalability in all kinds of distributed network topologies.");
  script_set_attribute(attribute:"see_also", value:"http://www.ressoftware.com/product/res-workspace-manager");
  script_set_attribute(attribute:"see_also", value:"https://support.ressoftware.com/workspacemanageradminguide2012/23720.htm");
  script_set_attribute(attribute:"solution", value:
"Make sure that use of this software is in agreement with your
organization's security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:res_software:res_workspace_manager_relay");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"Service detection");

  script_dependencies("netbios_name_get.nasl", "find_service1.nasl");
  script_require_keys('SMB/name');
  script_require_ports("Services/unknown", 1942);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery"))
{
  port = get_unknown_svc(1942);
  if (!port) audit(AUDIT_SVC_KNOWN);
}
else port = 1942;
if (known_service(port:port)) exit(0, "The service is already known on port "+port+".");
if (silent_service(port)) exit(0, "The service listening on port " + port + " is silent.");
if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

netbios_name = get_kb_item_or_exit('SMB/name');

request =
  '<request><cn>' +
  netbios_name +
  '</cn><proc>res</proc></request>\r\n';

request =
  raw_string(
    0x20, 0x02, 0x01, 0x0f, 0x01, 0x7a, 0xfc, 0x01,
    0x00, 0x01, 0x30, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xfd
  ) +
  unicode(string:request);

send(socket:soc, data:request);

response = recv(socket:soc, length:1024, min:128);

valid_response_1 = unicode(string:'<response iv=');
valid_response_2 = unicode(string:'<ssl>');

if (valid_response_1 >!< response || valid_response_2 >!< response) audit(AUDIT_RESP_BAD, port, 'a RES Workspace Manager Relay Server probe');

register_service(port:port, proto:'res_wm_relay');
security_note(port:port);
