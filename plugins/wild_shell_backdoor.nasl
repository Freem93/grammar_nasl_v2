#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(51988);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/06/08 17:53:42 $");

  script_name(english:"Rogue Shell Backdoor Detection");
  script_summary(english:"Detect rogue shells.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host may have been compromised.");
  script_set_attribute(attribute:"description", value:
"A shell is listening on the remote port without any authentication
being required. An attacker may use it by connecting to the remote
port and sending commands directly.");
  script_set_attribute(attribute:"solution", value:
"Verify if the remote host has been compromised, and reinstall the
system if necessary.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Backdoors");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", "Services/wild_shell");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

ports = make_list();

wsports = get_kb_list("Services/wild_shell");
if (!empty_or_null(wsports))
{
  foreach port (wsports)
  {
    if (get_port_state(port))
      ports = make_list (ports, port);
  }
}

if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery"))
{
  uports = get_kb_list("Services/unknown");
  if (!empty_or_null(uports))
  {
    foreach port (uports)
    {
      if (get_port_state(port) && service_is_unknown(port:port))
        ports = make_list (ports, port);
    }
  }
}

if(empty_or_null(ports)) exit(0, "No wild shell or unknown services to test against.");

ports = list_uniq(ports);

port = branch(ports);

soc = open_sock_tcp(port);
if ( ! soc ) audit(AUDIT_SOCK_FAIL, port);

cmds = make_list("id", "ipconfig");
flag = FALSE;

foreach cmd (cmds)
{
  request = cmd+'\n';

  send(socket:soc, data:request);
  r = recv(socket:soc, length:4096);
  if (empty_or_null(r)) continue;

  # Check for id command
  if ( "uid=" >< r  ||
        (
          "Microsoft Windows" >< r &&
          "C:\">< r &&
          egrep(pattern:"\([c|C]\) (Copyright )?([0-9]+)", string:r) &&
          "Microsoft Corp" >< r
        )
     ) flag = TRUE;

  # Check for ipconfig command
  if ( "Windows IP Configuration" >< r &&
       egrep(pattern:"IP(v4)? Address. . .", string:r)
     ) flag = TRUE;

  if (flag)
  {
    close(soc);
    security_report_v4(port:port, severity:SECURITY_HOLE, cmd:cmd, request:request, output:r);
    exit(0);
  }
}
close(soc);
audit(AUDIT_HOST_NOT, "affected");
