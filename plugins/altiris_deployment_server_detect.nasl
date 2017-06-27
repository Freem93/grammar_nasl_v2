#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25897);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2012/09/18 23:50:17 $");

  script_name(english:"Altiris Deployment Server Detection");
  script_summary(english:"Tries to detect Altiris Deployment Server");

 script_set_attribute(attribute:"synopsis", value:
"A deployment service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is running the Deployment Server component of
Altiris Deployment Solution, a product for centralized management of
computer systems throughout an enterprise." );
 script_set_attribute(attribute:"see_also", value:"http://www.altiris.com/Products/DeploymentSolution.aspx" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/08/15");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2012 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 402);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery") )
{
  port = get_unknown_svc(402);
  if (!port) exit(0);
}
else port = 402;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Send a request.
name = SCRIPT_NAME;
req = 
  'Request=SmartUpdate\n' +
    'ID=1\n' +
    'MAC-Address=00132003bd94\n' +
    'Name=' + name + '\n' +
    'Domain-Member=No\n' +
    'IP-Address=' + this_host() + '\n' +
    'Computer-Name=NESSUS\n' +
  mkbyte(0);
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);
close(soc);


# If it looks like a valid reply...
if (
  "Reply=SmartUpdate" >< res &&
  "Result=" >< res
)
{
  # Extract some interesting info for the report.
  info = "";
  # - server name.
  if ("Server-Name=" >< res)
  {
    name = strstr(res, "Server-Name=") - "Server-Name=";
    name = name - strstr(name, '\n');
    if (strlen(name))
    {
      info += "  Server name : " + name + '\n';
    }
  }
  # - Deployment Server version.
  if ("DSVersion=" >< res)
  {
    ver = strstr(res, "DSVersion=") - "DSVersion=";
    ver = ver - strstr(ver, '\n');
    if (ver =~ "^[0-9][0-9.]+$")
    {
      set_kb_item(name:"Altiris/DSVersion/"+port, value:ver);
      info += "  Version     : " + ver + '\n';
    }
  }

  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"axengine");

  if (info)
    report = string(
      "Nessus was able to gather the following information from the remote\n",
      "Altiris Deployment Server :\n",
      "\n",
      info
    );
  else report = NULL;
  security_note(port:port, extra:report);
}
