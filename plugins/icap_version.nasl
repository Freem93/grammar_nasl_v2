#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69928);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/09/18 00:31:18 $");

  script_name(english:"ICAP Server Type and Version");
  script_summary(english:"Send an OPTIONS request and examine the Server header.");

  script_set_attribute(attribute:"synopsis", value:"An ICAP server is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"This plugin attempts to determine the type and the version of the
remote ICAP server.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/icap", 1344);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

port = get_kb_item_or_exit("Services/icap");
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

hostname = get_host_name();

req =
  'OPTIONS icap://' + hostname + '/ ICAP/1.0\r\n' +
  '\r\n';

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

send(socket:soc, data:req);
res = recv(socket:soc, length:1024);

close(soc);

if ("ICAP/1.0 200" >!< res)
  exit(0, "The ICAP server listening on port " + port + " did not send a successful response.");

matches = eregmatch(string:res, pattern:"\r\nService: (.+)\r\n");
if (isnull(matches)) exit(0, "The ICAP server listening on port " + port + " did not provide a 'Service' response header.");
serv = matches[1];

matches = eregmatch(string:serv, pattern:"^ProxyAV +AV +scanner +([0-9.]+) *\((\d+)\)$");
if (!isnull(matches))
{
  kb = "icap/bluecoat_proxyav";
  set_kb_item(name:kb, value:port);
  set_kb_item(name:kb + "/" + port + "/version", value:matches[1]);
  set_kb_item(name:kb + "/" + port + "/release_id", value:matches[2]);
}

if (report_verbosity > 0)
{
  report =
    '\nThe remote ICAP server identifies itself as :' +
    '\n' +
    '\n  ' + serv +
    '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
