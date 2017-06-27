#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36088);
  script_version("$Revision: 1.5 $");

  script_name(english:"ZENworks Remote Management Agent Detection");
  script_summary(english:"Remotely detects a ZENworks remote management agent");

  script_set_attribute(
    attribute:"synopsis",
    value:"A remote management agent is listening on the remote host."
  );
  script_set_attribute(  attribute:"description",  value:
"The remote host is running ZENworks Remote Management Agent.  This
program allows a system to be managed remotely by an administrator."  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.novell.com/products/zenworks/"
  );
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/06");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_cvs_date("$Date: 2011/03/11 21:18:10 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 1761);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");


if (
  thorough_tests &&
  ! get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(1761);
  if (!port) exit(0);
  if (!silent_service(port)) exit(0);
}
else port = 1761; 
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);

soc = open_sock_tcp (port);
if (!soc) exit(0);

version_req = raw_string (0x00, 0x06, 0x05, 0x01, 0x10, 0xe6, 0x01, 0x00, 0x34, 0x5a, 0xf4, 0x77, 0x80, 0x95, 0xf8, 0x77);

send (socket:soc, data:version_req);
buf = recv (socket:soc, length:16);
if ((strlen(buf) != 16))
  exit(0);

vers_comp = raw_string (0x00, 0x01);
send (socket:soc, data:vers_comp);
buf = recv (socket:soc, length:2);

# Expecting either a two byte number, or nothing
if (strlen(buf) == 2) workstation_len = getword(blob:buf, pos:0);
else if (strlen (buf) == 0) workstation_len = -1;
else exit (0);

# The agent should reply with its workstation name
if (workstation_len > 1)
{
  workstation = recv (socket:soc, length:workstation_len);

  # If the workstation is registered, it should also reply with the
  # name of the tree it's registered with
  buf = recv (socket:soc, length:2);
  if (buf)
  {
    tree_name_len = getword(blob:buf, pos:0);
    tree_name = recv(socket:soc, length:tree_name_len);
  }

  if (workstation_len != strlen(workstation)) exit(0);
  if (tree_name_len != strlen(tree_name)) exit(0);
}

user = this_host() + '\\nessusscanner';
host = this_host();
auth_req =
  mkword(strlen(user)) + user +
  mkword(strlen(host)) + host +
  raw_string(0x00, 0x07) + "UNKNOWN" +
  raw_string(0x00, 0x01);
send (socket:soc, data:auth_req);
buf = recv (socket:soc, length:100, min:2);

# The agent will reject if it hasn't set a remote control password or
# if password authentication is disabled.  Otherwise, it's ready to
# continue the handshake
pw_auth_disabled = raw_string(0xff,0xfe);
no_pw_set = raw_string(0xff,0x9b);
accepted = raw_string(0x00,0x00);

if (buf == accepted || buf == no_pw_set || buf == pw_auth_disabled)
{
  register_service(port:port, proto:"zenworks_rma");

  report = '\nThe remote host reported the following information to Nessus :\n\n';

  if (workstation)
  {
    report += string("  Workstation name : ", workstation, "\n");

    set_kb_item(
      name:"Services/zenworks_rma/workstation_name",
      value:workstation
    );
  }
  if (tree_name)
  {
    report += string("  ZENworks tree : ", tree_name, "\n");

    set_kb_item(
      name:"Services/zenworks_rma/tree_name",
      value:tree_name
    );
  }

  if(report_verbosity > 0 && (workstation || tree_name))
    security_note(port:port, extra:report);
  else
    security_note(port);
}
