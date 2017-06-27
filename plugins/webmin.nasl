#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, changed family (4/13/2009)
# - Added CPE, updated version check, updated regex for detection of Webmin,
# added version grabbing from the HTTP banner, added global_settings.inc
# include file for reporting verbosity definition. (8/28/2014)

include("compat.inc");

if (description)
{
  script_id(10757);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2014/09/16 19:05:46 $");

  script_name(english:"Webmin Detection");
  script_summary(english:"Check for Webmin.");

  script_set_attribute(attribute:"synopsis", value:"An administration application is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running Webmin, a web-based interface for
system administration for Unix.");
  script_set_attribute(attribute:"see_also", value:"http://www.webmin.com/");
  script_set_attribute(attribute:"solution", value:
"Stop the Webmin service if not needed or ensure access is limited to
authorized hosts. See the menu items '[Webmin Configuration][IP Access
Control]' and/or '[Webmin Configuration][Port and Address]'.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2001/09/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:webmin:webmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2001-2014 Alert4Web.com");

  script_dependencie("httpver.nasl");
  script_require_ports("Services/www", 10000);
  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:10000);

dir = "/";
app = "Webmin";

banner = get_http_banner(port:port);
if (empty_or_null(banner))
  exit(1,"Unable to get the web server banner on port " + port + ".");

match = eregmatch(pattern:"(Server: MiniServ.*)", string:banner);
if (!empty_or_null(match[1])) banner = match[1];
else
  exit(0, "The web server on port " + port + " is not " + app + ".");

res = http_keepalive_send_recv(
  port : port,
  data : http_get(item:dir,port:port),
  embedded : TRUE
);

if (
  (!isnull(res)) &&
  (
    (egrep(pattern:"(login to )?webmin</b>", string:res, icase:TRUE)) ||
    ( ('Basic realm="Webmin Server' >< res) &&
    ("401 Unauthorized" >< res) )
  )
)
{
  set_kb_item(name:"www/webmin", value:TRUE);
  set_kb_item(name:"www/" + port + "/webmin", value:TRUE);
  set_kb_item(name:"www/webmin/" + port + "/source", value:banner);
  set_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE);

  version = NULL;
  # Only 0.8x versions supplied version info on the index page
  match = eregmatch(
    pattern : "logged into Webmin (0\.8[0-9])",
    string  : res
  );

  if (!empty_or_null(match[1])) version = match[1];
  # Grab version from HTTP banner
  else
  {
    match = eregmatch(
      pattern : "Server: MiniServ/([0-9\.]+)",
      string  : banner
    );
    if (!empty_or_null(match[1])) version = match[1];

  }
  # Can only grab an accurate version starting with 1.530.
  if (empty_or_null(version))
    version = 'unknown';

  set_kb_item(name:"www/webmin/" + port + "/version",value:version);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL            : ' + build_url(qs:'/', port:port) +
      '\n  Source         : ' + banner +
      '\n  Webmin version : ' + version + '\n';

    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
exit(0, app + " was not detected on the web server on port " + port + ".");
