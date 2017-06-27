#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42058);
  script_version("$Revision: 1.4 $");

  script_name(english:"Dopewars Server Detection");
  script_summary(english:"Tries to join a dopewars game");

  script_set_attribute(
    attribute:"synopsis",
    value:"A game server is running on the remote host."
  );
  script_set_attribute(attribute:"description", value:
"Dopewars is a text-based drug dealing game.  A dopewars server was
detected on the remote host."  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sourceforge.net/projects/dopewars/"
  );
  script_set_attribute( attribute:"solution", value:
"Make sure that use of this program agrees with your organization's
acceptable use and security policies."  );
  script_set_attribute(
    attribute:"risk_factor",
    value:"None"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/10/07"
  );
 script_cvs_date("$Date: 2011/03/11 21:18:08 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/dopewars", 7902);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(7902);
  if (!port) exit(0);
  if (!silent_service(port)) exit(0, "The service on TCP port "+port+" is not silent.");
}
else port = 7902;
if (known_service(port:port)) exit(0, "The service on TCP port "+port+" has already been identified.");
if (!get_tcp_port_state(port)) exit(1, "Port "+port+" is closed.");

soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open a socket on TCP port "+port+".");

from = SCRIPT_NAME;
to = unixtime();
req = string(
  from, "^", to, "^Ar1111111\n",  # C_ABILITIES message
  "^^Ac", from, "\n"              # C_NAME message
);

send(socket:soc, data:req);

# Increases the timeout, in case the server has problems reaching the metaserver
res = recv_line(socket:soc, length:256, timeout:15);
if (isnull(res)) exit(1, "The server on port "+port+" didn't respond.");

# Newer versions of the server will first respond with a warning message about
# using the older version of the protocol. Skip this and get the next message.
if (ereg(string:res, pattern:"^\^\^PAYou appear to be using an extremely old"))
{
  res = recv_line(socket:soc, length:256);
  if (isnull(res)) exit(1, "The server on port "+port+" didn't respond.");
}

# The server should respond with a C_ABILITIES message
if (ereg(string:res, pattern:"^[^\^]*\^[^\^]*\^Ar[01]+$"))
{
  register_service(port:port, proto:"dopewars");

  # Try to get a version number from the C_INIT message
  res = recv_line(socket:soc, length:256);
  if (!isnull(res))
  {
    match = eregmatch(string:res, pattern:"^[^\^]*\^[^\^]*\^Ak([^\^]+)\^");
    if (match)
    {
      ver = match[1];
      set_kb_item(name:'dopewars/' + port + '/ver', value:ver);
    }
  }

  if (report_verbosity > 0 && ver)
  {
    report = string("\nVersion : ", ver, "\n");
    security_note(port:port, extra:report);
  }
  else security_note(port);

  exit(0);
}
else exit(0, "A C_ABILITIES message wasn't received on port "+port+".");
