#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49658);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/09 00:11:25 $");

  script_name(english:"Syncrify Detection");
  script_summary(english:"Looks for evidence of Syncrify");

  script_set_attribute(attribute:"synopsis", value:"The remote host is running a web-based backup application.");

  script_set_attribute(attribute:"description", value:
"The remote host is running Syncrify, a web-based incremental backup
application.");

  script_set_attribute(attribute:"see_also", value:"http://web.synametrics.com/Syncrify.htm");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 5800);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:5800);

version = NULL;

# Unless we're paranoid, make sure the banner looks like Tomcat.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port, exit_on_fail: 1);
  if ("Server: Apache-Coyote" >!< banner) exit(0, "The banner from the web server on port "+port+" does not look like Apache Tomcat.");
}

res = http_get_cache(item:'/app', port:port, exit_on_fail:TRUE);
if (
  'Syncrify - Fast incremental backup - Version:' >< res &&
  '<a href="http://web.synametrics.com/Syncrify.htm">Syncrify Home</a>' >< res
)
{
  pattern = 'Syncrify - Fast incremental backup - Version: ([0-9\\.]+ - build [0-9]+)';
  matches = egrep(pattern:pattern, string:res);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pattern, string:match);
      if (!isnull(item))
      {
        version = item[1];
        break;
      }
    }
  }

  installs = add_install(
    installs:installs,
    ver:version,
    dir:'/app',
    appname:'syncrify',
    port:port
  );
}

if (isnull(installs)) exit(0, "Syncrify wasn't detected on port "+port+".");

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'Syncrify',
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
