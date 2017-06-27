#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30105);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2011/03/11 21:18:07 $");

  script_name(english:"AXIMilter Detection");
  script_summary(english:"Tries to send an empty message");

 script_set_attribute(attribute:"synopsis", value:
"A messaging service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is an AXIGEN milter filtering daemon, also known as
AXIMilter, which is used by AXIGEN to interface with third-party
milters such as Avira MailGate, Symantec Brightmail AntiSpam, etc." );
 script_set_attribute(attribute:"see_also", value:"http://www.axigen.com/" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/01/28");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 1981);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("url_func.inc");


if (
  thorough_tests && 
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(1981);
  if (!port) exit(0);
  if (silent_service(port)) exit(0); 
}
else port = 1981;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Have it check a message with a nonexistent file.
crlf = "\r\n";
file = string(SCRIPT_NAME, "-", unixtime());

req = string(
  "FROM: <>", crlf, 
  "EHLO: ", this_host_name(), crlf,
  "CNIP: ", this_host(), crlf,
  "CNPO: ", port, crlf,
  "CNHO ", get_host_name(), crlf,
  "RCPT: <postmaster@", get_host_name(), ">", crlf,
  "VERI: ", file, crlf
);
send(socket:soc, data:req);
res = recv_line(socket:soc, length:256);
if (res == NULL) exit(0);


# Register and report the service if it looks like an AXIMilter error.
res = chomp(res);
res = urldecode(estr:res);

if (
  "ERROR: Could not connect to Milter implementation" == res ||
  "ERROR: Could not open message file" == res
)
{
  register_service(port:port, ipproto:"tcp", proto:"aximilter");
  security_note(port);
}
