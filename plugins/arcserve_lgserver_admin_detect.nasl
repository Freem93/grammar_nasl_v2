#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24239);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/04/28 14:01:58 $");

  script_name(english:"ARCserve Backup for Laptops & Desktops Server Admin Service Detection");
  script_summary(english:"Detects ARCserve Backup for Laptops & Desktops via discovery");

  script_set_attribute(attribute:"synopsis", value:
"There is a backup service running on the remote host.");
  script_set_attribute(attribute:"description", value:
"BrightStor ARCserve Backup for Laptops & Desktops Server (formerly
BrightStor Mobile Backup Server), an enterprise class backup solution
for remote and mobile Windows-based PCs, is installed on the remote
host.  And the service listening on this port is used by the
application's Server Explorer to administer ARCserve Backup for
Laptops & Desktops Server remotely.");
  script_set_attribute(attribute:"see_also", value:"https://www.ca.com/us.html");
  script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port to hosts using Server Explorer.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:brightstor_arcserve_backup_laptops_desktops");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_dependencies("find_service_3digits.nasl");
  script_require_ports("Services/unknown", 1900);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery") )
{
  port = get_unknown_svc(1900);
  if (!port) exit(0);
}
else port = 1900;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


# Make sure the response to a HELP command looks right, unless we're being paranoid.
if (report_paranoia < 2)
{
  help = get_kb_banner(port: port, type: "help");
  if (!isnull(help) && "0~~[32049] unknown function:" >!< help) exit(0, "The response to a 'HELP' isn't from ARCserve.");
}


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Send some requests to gather some info.
info = "";
cmds = make_list(
  "rxrGetServerVersion", 
  "rxsGetComputerName", 
  "rxsGetDatabaseDir",
  "rxsGetDefaultConfigName", 
  "rxsGetRootOrganization"
);
foreach cmd (cmds)
{
  req = string(strlen(cmd));
  req = string(crap(data:'0', length:10-strlen(req)), req, cmd);
  send(socket:soc, data:req);

  len = recv(socket:soc, length:10);
  if (strlen(len) == 10 && int(len) > 0)
  {
    res = recv(socket:soc, length:int(len));
    if (res == NULL) exit(0);

    # If we got a valid response...
    if (substr(res, 0, 2) == "1~~")
    {
      if (cmd == "rxrGetServerVersion") 
      {
        ver = substr(res, 3);
        info += "  Version :            " + ver + '\n';
        set_kb_item(name:"ARCSERVE/LGServer/Version", value:ver);

      }
      else if (cmd == "rxsGetComputerName")
      {
        info += "  Computer name :      " + substr(res, 3) + '\n';
      }
      else if (cmd == "rxsGetDatabaseDir")
      {
        info += "  Database directory : " + substr(res, 3) + '\n';
      }
      else if (cmd == "rxsGetDefaultConfigName")
      {
        info += "  Default config :     " + substr(res, 3) + '\n';
      }
      else if (cmd == "rxsGetRootOrganization")
      {
        info += "  Root organization :  " + substr(res, 3) + '\n';
      }
    }
  }
}


# Register and report the service if we were able to collect some info.
if (info)
{
  register_service(port:port, ipproto:"tcp", proto:"lgserver_admin");

  report = string(
    "Nessus was able to collect the following information from the\n",
    "discovery service running on the remote host :\n",
    "\n",
    info
  );
  security_note(port:port, extra:report);
}
