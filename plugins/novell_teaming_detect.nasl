#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(47803);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/09 00:11:23 $");

  script_name(english:"Novell Teaming Detection");
  script_summary(english:"Checks for Novell Teaming");

  script_set_attribute(attribute:"synopsis", value:"The remote web server hosts a web-based collaboration tool.");

  script_set_attribute(attribute:"description", value:
"The remote web server hosts Novell Teaming, a web-based collaboration
application.");

  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/products/teaming/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

dir = '/';

url = dir + '/';
res = http_send_recv3(method:"GET", item:url, port:port, follow_redirect:3, exit_on_fail:TRUE);

# Older versions do the initial redirect with
# location.replace()
if (
  '<body onload="javascript:location.replace(' >< res[2]
)
{
  pattern = '<body onload="javascript:location.replace\\(\'([^\']+)\'';
  matches = egrep(pattern:pattern, string:res[2], icase:FALSE);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pattern, string:match);
      if (!isnull(item))
      {
        res = http_send_recv3(method:"GET", item:url+item[1], port:port, follow_redirect:2, exit_on_fail:TRUE);
      }
    }
  }
}

if (
  '<title>Novell Teaming - Welcome!</title>' >< res[2] ||
  (
    '<title>Please Sign In</title>' >< res[2] &&
    'alt="About Novell Teaming"' >< res[2]
  )
)
{
  installs = add_install(
    installs:installs,
    dir:dir,
    appname:'novell_teaming',
    port:port
  );
}

if (isnull(installs)) exit(0, 'Novell Teaming wasn\'t detected on port '+port+'.');

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'Novell Teaming',
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
