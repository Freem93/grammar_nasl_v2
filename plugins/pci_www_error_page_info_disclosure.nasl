#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88490);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/02/02 21:28:13 $");

  script_name(english:"Web Server Error Page Information Disclosure");
  script_summary(english:"Checks for server and versions on error page.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server discloses information via a default error page.");
  script_set_attribute(attribute:"description", value:
"The default error page sent by the remote web server discloses
information that can aid an attacker, such as the server version and
languages used by the web server.");
  script_set_attribute(attribute:"solution", value:
"Modify the web server to not disclose detailed information about the
underlying web server, or use a custom error page instead.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "tomcat_error_version.nasl", "apache_http_version.nasl", "iis_detailed_error.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Reporting function
function vreport(type, source, version, port)
{
  local_var report;
  report = '';

  # Should never be reached
  if (empty_or_null(version))
    exit(0, "Nessus was unable to extract version information from the error page found when requesting a non-existent page on the web server on port "+port+".");

  report +=
    '\n  Server Type    : ' + type +
    '\n  Server Version : ' + version +
    '\n  Source         : ' + build_url(qs:source, port:port) +
    '\n';

  if (report_verbosity > 0)
    security_warning(port:port, extra:report);
  else security_warning(port);
  exit(0);
}

# Code starts here
port = get_http_port(default:80);

err_page = '/' + rand_str();
vuln = FALSE;
type = NULL;
source = NULL;
server_ver = NULL;
server_pats = make_array();

apache = make_array("regex", "<address>(Apache/[0-9\.]+) Server at (.+) Port ([0-9]+)</address>", "match", "1");
tomcat = make_array("regex", "<title>Apache Tomcat/([0-9\.]+) - Error report", "match", "1");
cern = make_array("regex", '<ADDRESS><A HREF="(.*)">CERN(/| httpd )([0-9\\.]+($|.*[^<]))</A>', "match", "3");
iis = make_array("regex", '<title>IIS ([0-9\\.]+) Detailed Error.+</title>($|[^\n])', "match", "1");
knet = make_array("regex", "<hr><center>KNET WEB SERVER/([0-9\.]+)</center>", "match", "1");
nginx = make_array("regex", "<hr><center>nginx/(.*)</center>", "match", "1");
oracle = make_array("regex", "<ADDRESS>Oracle-Application-Server-([0-9\.]+($|[^\s]+)).* Port ([0-9]+)</ADDRESS>", "match", "1");

#
# Check and see if we have already identified the server based
# on existing plugins
#
######################################################################
# Apache
######################################################################
chk_apache = get_kb_item("www/" + port + "/apache");
if (chk_apache)
  server_pats = make_array("Apache", apache);

######################################################################
# Apache Tomcat
######################################################################
chk_tomcat = get_kb_item("www/"+port+"/tomcat");
if (chk_tomcat)
  server_pats = make_array("Apache Tomcat", tomcat);

######################################################################
# Microsoft IIS
# iis_detailed_error.nasl collects info from a non-existent page
# so report the info saved by this plugin
######################################################################
chk_iis = get_kb_item("www/"+port+"/iis_detailed_errors");
if (chk_iis)
{
  type = 'Microsoft IIS';
  server_ver = get_kb_item("www/"+port+"/iis_version");

  if (empty_or_null(server_ver)) server_ver = NULL;
  else vuln = TRUE;

  source =  get_kb_item("www/"+port+"/iis_version_from");
  if (empty_or_null(source)) source = NULL;

  if (vuln)
    vreport(type:type, source:source, version:server_ver, port:port);
}

# Check if we have a server listed in the HTTP banner.  If so we can
# reduce the number of requests
if ((!chk_apache) && (!chk_iis) && (!chk_tomcat) && (!vuln))
{
  banner = get_http_banner(port: port, exit_on_fail:FALSE);
  if (!empty_or_null(banner))
    server = egrep(string:banner, pattern:"^Server:", icase:TRUE);

  if (!empty_or_null(server))
  {
    server = ereg_replace(
       string  : chomp(server),
       pattern : "^Server: *",
       replace : "",
       icase   : TRUE
    );
    ######################################################################
    # CERN httpd
    ######################################################################
    if (ereg(pattern:"^(CERN httpd(\s)?|CERN/)", string:server, icase:TRUE))
      server_pats = make_array("CERN", cern);
    ######################################################################
    # KNet Web Server
    ######################################################################
    if (server =~ "^KNet")
     server_pats = make_array("KNet Web Server", knet);
    ######################################################################
    # NGINX
    ######################################################################
    if (tolower(server) =~ "^nginx")
      server_pats = make_array("NGINX", nginx);
    ######################################################################
    # Oracle Application Server
    ######################################################################
    if (server =~ "^Oracle-Application-Server")
      server_pats = make_array("Oracle Application Server", oracle);
  }
}

# Otherwise build an array with each of our server types and patterns
if (max_index(keys(server_pats)) == 0)
{
  server_pats = make_array(
    "Apache", apache,
    "Apache Tomcat", tomcat,
    "CERN", cern,
    "Microsoft IIS", iis,
    "KNet Web Server", knet,
    "NGINX", nginx,
    "Oracle Application Server", oracle
  );
}

exts = make_list("", ".", ".htm", ".html");
if (thorough_tests)
{
  exts = make_list(exts, ".php", ".asp", ".aspx", ".asmx", ".jsp", ".jspx",
    ".shtml", ".cfm", ".cgi", ".pl", ".do", ".jsf", ".faces", ".php4", ".php5");
}

foreach ext (exts)
{
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : err_page + ext,
    fetch404     : TRUE,
    exit_on_fail : TRUE
  );
  if (res[0] =~ "^HTTP/.* 2[0-9][0-9]($|[^\n]+)") continue;

  foreach type (keys(server_pats))
  {
    matches = eregmatch(
      pattern : server_pats[type]["regex"],
      string  : res[2],
      icase   : TRUE
    );
    if (!empty_or_null(matches))
    {
       match_pos = int(server_pats[type]["match"]);
       server_ver = matches[match_pos];
       vreport(type:type, source:err_page+ext, version:server_ver, port:port);
    }
  }
}
exit(0, "The web server on port "+port+" does not disclose sensitive information on the error page returned for a non-existent page.");
