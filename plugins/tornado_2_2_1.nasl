#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59356);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/05/24 02:20:54 $");

  script_cve_id("CVE-2012-2374");
  script_bugtraq_id(53612);
  script_osvdb_id(82027);

  script_name(english:"Tornado < 2.2.1 HTTP Response Splitting");
  script_summary(english:"Checks version in Server response header");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server may be affected by an HTTP response splitting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Tornado installed on the
remote host is older than 2.2.1.  As such, it may be affected by an
HTTP response splitting vulnerability that may allow an
unauthenticated, remote attacker to forge responses from a trusted
server.");

  script_set_attribute(attribute:"see_also", value:"http://openwall.com/lists/oss-security/2012/05/18/12");
   # https://github.com/facebook/tornado/commit/1ae91f6d58e6257e0ab49d295d8741ce1727bdb7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52c27e32");
  script_set_attribute(attribute:"see_also", value:"http://www.tornadoweb.org/documentation/releases/v2.2.1.html");

  script_set_attribute(attribute:"solution", value:
"Update to version 2.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tornadoweb:tornado");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/tornado", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

app = "Tornado";

get_kb_item_or_exit("www/tornado");

# Prevent potential false positives.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Get the ports that webservers have been found on.
port = get_http_port(default:80);

# Get the Server response headers.
srv = http_server_header(port:port);
if (isnull(srv))
  exit(0, "The web server listening on port " + port + " does not send a Server response header.");

# Check if the webserver is Tornado.
regex = "^TornadoServer";
if (srv !~ regex)
  audit(AUDIT_WRONG_WEB_SERVER, port, app);

# Extract the version number from the Server header.
matches = eregmatch(string:srv, pattern:regex + "/([0-9.]+)");
if (isnull(matches)) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, app, port);
ver = matches[1];

# Check if the webserver is affected.
fix = "2.2.1";
if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_LISTEN_NOT_VULN, app, port, ver);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  Source            : ' + srv +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
}

security_warning(port:port, extra:report);
