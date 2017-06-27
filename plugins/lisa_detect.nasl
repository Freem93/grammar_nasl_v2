#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33200);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2011/03/11 21:18:09 $");

  script_name(english:"LISa Detection");
  script_summary(english:"Grabs list of hosts");

 script_set_attribute(attribute:"synopsis", value:
"A 'network neighborhood' service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is a LISa server (LAN Information Server), which
provides a list of nearby hosts, like a 'network neighborhood', but
based solely on TCP/IP." );
 script_set_attribute(attribute:"see_also", value:"http://lisa-home.sourceforge.net/" );
 script_set_attribute(attribute:"solution", value:
"Limit access to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/06/17");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 7741);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(7741);
  if (!port) exit(0);
  if (silent_service(port)) exit(0); 
}
else port = 7741;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Read the banner.
max = 10240;
res = recv(socket:soc, length:max);
close(soc);
if (strlen(res) == 0) exit(0);


# Make sure the response looks right.
lines = split(res, sep:'\n\x00', keep:FALSE);
foreach line (lines)
{
  if (line !~ "^[0-9]+ [a-zA-Z0-9.-]+$") exit(0);
}
# nb: make sure last line ends with '0 succeeded' as long as we read everything.
if (strlen(res) < max && line != '0 succeeded') exit(0);


# Register and report the service.
register_service(port:port, proto:"lisa");

if (report_verbosity > 1)
{
  report = string(
    "Here are the hosts known to the LISa server on the remote host :\n",
    "\n"
  );
  foreach line (lines)
    if (line !~ "0 succeeded") report += '  ' + line + '\n';
  report = string(
    report,
    "\n",
    "Note: each line consists of a decimal IP address in network byte order\n",
    "      and the corresponding hostname separated by a space.\n"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
