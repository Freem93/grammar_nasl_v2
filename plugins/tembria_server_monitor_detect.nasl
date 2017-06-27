#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46202);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2011/03/15 18:34:12 $");

  script_name(english:"Tembria Server Monitor Detection");
  script_summary(english:"Checks for Tembria Server Monitor");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a server monitoring application.");

  script_set_attribute(attribute:"description", value:
"The remote Windows host is running Tembria Server Monitor.  Tembria
Server Monitor is a server- and network-monitoring application that
contains a built-in web server.");

  script_set_attribute(attribute:"see_also", value:"http://www.tembria.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/30");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  
  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, asp:TRUE, embedded:TRUE);

# Make sure the banner looks like Tembria unless we're paranoid.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port, exit_on_fail: 1);
  if (!egrep(pattern:'^Server: TembriaWebServer/', string:banner))
    exit(0, "The web server on port "+port+" isn't Tembria.");
}

res = http_get_cache(port:port, item:"/tembria/index.asp", exit_on_fail:TRUE);
build = NULL;
version = NULL;

# Pull the build number and version info from the JavaScript.
if (
  '<title>Tembria Server Monitor</title>' >< res &&
  'Welcome to Tembria Server Monitor' >< res
)
{
  pat = 'BuildNumberAndVersion="<result>.*</result><buildno>([0-9]+)</buildno><version>v([0-9\\.]+)</version>"';
  matches = egrep(pattern:pat, string:res);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        build = item[1];
        version = item[2];
      }
    }
  }
  if (isnull(version)) version = 'unknown';
  if (isnull(build)) build = 'unknown';

  set_kb_item(name:"www/tembria_monitor", value:TRUE);
  set_kb_item(name:"www/tembria_monitor/"+port+"/version", value:version);
  set_kb_item(name:"www/tembria_monitor/"+port+"/build", value:build);

  if (report_verbosity > 0)
  {
    report = 
      '\n  Product : Tembria Server Monitor' +
      '\n  Version : ' + version + 
      '\n  Build   : ' + build + '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else exit(0, "Tembria Server Monitor was not detected on port "+port+".");
