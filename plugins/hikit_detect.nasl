#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78429);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/09/24 21:08:39 $");

  script_name(english:"Hikit Backdoor Detection");
  script_summary(english:"Detects an installation of the Hikit backdoor server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host runs a potentially malicious remote administration
tool.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a Hikit backdoor client. Hikit is a remote
administration tool (RAT) used to control computers infected by
malware. The 'client' component is used to control those computers and
is associated with malicious activity.");
  script_set_attribute(attribute:"solution", value:
"Run local scans of the target host and all other potentially infected hosts using appropriate malware detection and removal tools.");
  script_set_attribute(attribute:"risk_factor", value:"Critical");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:hikit:hikit");
  script_set_attribute(attribute:"malware", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Backdoors");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");

function detect_hikit_gen10()
{
  local_var soc;
  soc = _FCT_ANON_ARGS[0];

  send(socket:soc, data:'GET /password HTTP/1.1\r\n\r\n');

  local_var response;
  response = recv(socket:soc, length:256);
  if (isnull(response))
  {
    return FALSE;
  }

  # Read and check magic.
  local_var magic;
  magic = stridx(response, ".welcome.");
  if (magic != 0)
  {
    return FALSE;
  }

  return TRUE;
}

function detect_hikit_gen12()
{
  local_var soc;
  soc = _FCT_ANON_ARGS[0];
  send(socket:soc, data:'GET / HTTP/1.1\r\n');

  local_var response;
  response = recv(socket:soc, length:256);

  if (isnull(response) || strlen(response) < 100)
  {
    return FALSE;
  }

  # Read and check magic.
  local_var etag, magic, response2, etag_endofline;
  etag = stridx(response, "ETag:");
  if (etag == -1)
  {
    return FALSE;
  }

  response2 = substr(response, etag);
  if (isnull(response2))
  {
    return FALSE;
  }

  magic = stridx(response2, "75BCD15");
  etag_endofline = stridx(response2, '\r\n');

  if (etag > -1 &&
      magic > -1 &&
      etag_endofline > -1 &&
      magic < etag_endofline)
  {
    return TRUE;
  }

  return FALSE;
}

port = get_http_port(default:80);
if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);
detected10 = detect_hikit_gen10(soc);
close(soc);

if (detected10)
{
  register_service(port:port, ipproto:"tcp", proto:"hikit");
  security_hole(port:port);
  exit(0);
}

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);
detected12 = detect_hikit_gen12(soc);
close(soc);

if (detected12)
{
  register_service(port:port, ipproto:"tcp", proto:"hikit");
  security_hole(port:port);
  exit(0);
}

audit(AUDIT_NOT_DETECT, "Hikit backdoor", port);
