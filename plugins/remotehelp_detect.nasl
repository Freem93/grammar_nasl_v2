#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45139);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2011/03/15 18:34:12 $");

  script_name(english:"Remote Help Detection");
  script_summary(english:"Checks for the Remote Help web server");

  script_set_attribute(attribute:"synopsis", value:
"A web-based remote control application is installed on the remote
host."
  );
  script_set_attribute(attribute:"description", value:
"The remote host is running Remote Help, a web server for Windows that
can be used to control the host."
  );
  script_set_attribute(attribute:"see_also", value:"http://remotehelp.sourceforge.net/en/index.html");
  script_set_attribute(attribute:"solution", value:
"Make sure that use of this software agrees with your organization's
acceptable use and security policies."
  );
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/24");
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

port = get_http_port(default:80, embedded:TRUE);

# Make sure the banner looks correct unless we're paranoid.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (banner && !egrep(pattern:'^Server: httpd [0-9\\.]+', string:banner))
    exit(0, "The web server on port "+port+" isn't Remote Help.");
}

res = http_get_cache(item:"/", port:port, exit_on_fail:TRUE);

version = NULL;
if (
  '<TITLE>Welcome</TITLE>' >< res &&
  '<a href=http://remotehelp.sf.net>Remote Help </a>(httpd' >< res
)
{
  version = 'unknown';

  pattern = 'Remote Help </a>\\(httpd ([0-9.]+)\\)';
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

  set_kb_item(name:"www/remote_help", value:TRUE);
  set_kb_item(name:"www/remote_help/"+port, value:version);

  if (report_verbosity > 0)
  {
    report = '\n  Version : ' + version + '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else exit(0, "Remote Help was not detected on port "+port+".");
