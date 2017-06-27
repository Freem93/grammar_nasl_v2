#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30057);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2011/09/14 19:48:34 $");

  script_name(english:"nagios-statd Daemon Detection");
  script_summary(english:"Sends commands such as 'version', 'disk', and 'proc'");

  script_set_attribute(attribute:"synopsis", value:
"A system monitoring service is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote service is a nagios-statd daemon, a system monitoring tool
designed to be integrated with Nagios, although it can also be used
without that.");
  script_set_attribute(attribute:"see_also", value:"http://www.twoevils.org/files/netsaint_statd/");
  script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port as it can reveal sensitive
information about the remote host.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 1040);

  exit(0);
}



include("global_settings.inc");
include("misc_func.inc");


if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(1040);
  if (!port) exit(0);
  if (silent_service(port)) exit(0); 
}
else port = 1040;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


# Send a "version" command.
tries = 5;
for (i=0; i<tries; i++)
{
  soc = open_sock_tcp(port);
  if (soc)
  {
    req = "version";
    send(socket:soc, data:string(req, "\r\n"));
    res = "";
    while (line = recv_line(socket:soc, length:80))
    {
      res += line;
      if ( strlen(res) > 1024*1024 ) exit(1, "Bad protocol");
    }
    close(soc);

    if (strlen(res)) break;
    else sleep(1);
  }
}
if (res == NULL) exit(0);

# If it's nagios-statd...
if (strlen(res) && "nagios-statd" >< res)
{
  # Extract version if possible.
  ver = strstr(res, "nagios-statd") - "nagios-statd";
  if (ver =~ " [0-9]+\.")
  {
    ver = ver - " ";
    set_kb_item(name:"nagios_statd/"+port+"/Version", value:ver);
  }
  else ver = "";

  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"nagios_statd");

  if (report_verbosity)
  {
    # Collect some info for the report.
    info = "";
    # - version.
    if (ver) info += '  Version    : ' + ver + '\n\n';
    # - disk check.
    soc = open_sock_tcp(port);
    if (soc)
    {
      req = "disk";
      send(socket:soc, data:string(req, "\r\n"));
      res = "";
      while (line = recv_line(socket:soc, length:80))
      {
        res += '    ' + line;
        if ( strlen(res) > 1024*1024 ) exit(1, "Bad protocol");
      }
      if (strlen(res)) info += '  Disk usage :\n' + res + '\n';
      close(soc);
    }
    # - processes check.
    soc = open_sock_tcp(port);
    if (soc)
    {
      req = "proc";
      send(socket:soc, data:string(req, "\r\n"));
      res = "";
      while (line = recv_line(socket:soc, length:80))
      {
        res += '    ' + line;
        if ( strlen(res) > 1024*1024 ) exit(1, "Bad protocol");
      }
      if (strlen(res)) info += '  Processes  :\n' + res + '\n';
      close(soc);
    }

    report = string(
      "\n",
      "Nessus collected the following information from the remote\n",
      "nagios-statd daemon :\n",
      "\n",
      info
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
