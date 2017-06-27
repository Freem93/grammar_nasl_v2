#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70290);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/10/03 17:36:12 $");

  script_name(english:"RES Workspace Manager Agent Detection");
  script_summary(english:'Identifies RES Workspace Manager agents');

  script_set_attribute(attribute:"synopsis", value:"A RES Workspace Manager Agent is running on this port.");
  script_set_attribute(attribute:"description", value:
"The remote service is a RES Workspace Manager Agent.  It communicates
with a central database of RES Workspace Manager, a workspace
virtualization platform, and provides transaction services to the RES
Workspace Composer.  It usually indicates that this machine has the RES
Workspace Composer installed.  The RES Workspace Composer is the uniform
workspace that the end users of the RES Workspace Manager Workspace
virtualization platform interact with.");
  script_set_attribute(attribute:"see_also", value:"http://www.ressoftware.com/product/res-workspace-manager");
  script_set_attribute(attribute:"see_also", value:"https://support.ressoftware.com/workspacemanageradminguide/17791.htm");
  script_set_attribute(attribute:"solution", value:
"Make sure that use of this software is in agreement with your
organization's security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:res_software:res_workspace_manager_agent");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"Service detection");

  script_dependencies("find_service1.nasl");
  script_require_ports(1942);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

port = 1942;
if (known_service(port:port)) exit(0, "The service is already known on port "+port+".");
if (silent_service(port)) exit(0, "The service listening on port " + port + " is silent.");
if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

request = '';
request =
  raw_string(
    0x20, 0x02, 0x01, 0x0f, 0x01, 0x7a, 0xfc, 0x01,
    0x00, 0x01, 0x30, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xfd
  ) +
  unicode(string:request);

send(socket:soc, data:request);

response = recv(socket:soc, length:1024, min:1);

if (unicode(string:'FD0D11D7FE61BDD3BFE0E4EBD6') >!< response) audit(AUDIT_RESP_BAD, port, 'a RES Workspace Manager Agent probe');

register_service(port:port, proto:'res_wm_agent');
security_note(port:port);
