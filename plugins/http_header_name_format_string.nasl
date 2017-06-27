#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15641);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2014/05/26 00:21:38 $");

  script_name(english:"HTTP Header Name Remote Format String");
  script_summary(english:"Sends an HTTP request with %s in an HTTP header name");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is prone to a remote format string attack.");
  script_set_attribute(attribute:"description", value:
"The remote web server seems to be vulnerable to a remote format string
attack based on the way it responds to a request containing a header
whose name includes a format string. An anonymous attacker may be able
to leverage this flaw to make the affected service crash or to execute
arbitrary code on this host.");
  script_set_attribute(attribute:"solution", value:
"Upgrade the software or contact the vendor and inform them of this
vulnerability.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");

  script_dependencie("http_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

if (http_is_dead(port: port)) exit(0);

u = strcat("/nessus", rand_str(), ".html");
w = http_send_recv3(method:"GET", item: u, port: port);
if (isnull(w)) exit(0);

r = strcat(w[0], w[1], '\r\n', w[2]);

flag = 0; flag2 = 0;
if (egrep(pattern:"[0-9a-fA-F]{8}", string: r))
{
  flag = 1;
  debug_print('Normal answer:\n', r);
}

foreach bad (make_list("%08x", "%s", "%#0123456x%08x%x%s%p%n%d%o%u%c%h%l%q%j%z%Z%t%i%e%g%f%a%C%S%08x%%#0123456x%%x%%s%%p%%n%%d%%o%%u%%c%%h%%l%%q%%j%%z%%Z%%t%%i%%e%%g%%f%%a%%C%%S%%08x"))
{
  w = http_send_recv3(method:"GET", item: u, port: port,
     add_headers: make_array("Nessus-"+bad, "Nessus"));
  r = strcat(w[0], w[1], '\r\n', w[2]);
  if (isnull(w)) break;
  if (egrep(pattern:"[0-9a-fA-F]{8}", string: r))
  {
    debug_print('Format string:\n', r);
    flag2 ++;
  }
}

if ( http_is_dead(port:port, retry: 3) )   security_hole(port);


