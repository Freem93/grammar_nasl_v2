#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61448);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/08 01:22:19 $");

  script_name(english:"Horde Kronolith Detection");
  script_summary(english:"Checks for a presence of Kronolith");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a calendar web application.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts Kronolith, a PHP-based calendar
application from the Horde Project.");
  script_set_attribute(attribute:"see_also", value:"http://www.horde.org/apps/kronolith/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:horde:kronolith");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("horde_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/horde","www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

# nb: Horde is a prerequisite.
horde_install = get_install_from_kb(
  appname      : "horde",
  port         : port,
  exit_on_fail : TRUE
);
horde_dir = horde_install["dir"];

# Search for version number in a couple of different pages
files = make_list(
  'menu',
  'about'
);

# patterns for version info
file_pats = make_array();
file_pats['menu'] = ">Kronolith H[0-9]+ \(([0-9]+\.[^<]+)\)</span>";
file_pats['about'] = ">This is Kronolith +(.+)\.<";

if (thorough_tests) dirs = list_uniq(make_list("/calendar", "/kronolith", horde_dir+"/kronolith", cgi_dirs()));
else dirs = cgi_dirs();

installs = make_array();
foreach dir (dirs)
{
  url = dir + "/index.php";
  res = http_send_recv3(
    method          : "GET",
    item            : url,
    port            : port,
    exit_on_fail    : TRUE,
    follow_redirect : 1
  );

  if (
    'The Horde Project.  Kronolith is under the GPL.  -->' >< res[2] ||
    'javascript.php?file=goto.js&amp;app=kronolith"></script>' >< res[2] ||
    'var Kronolith' >< res[2] ||
    '<div id="kronolithHeader">' >< res[2] ||
    'name="app" id="app" value="kronolith"' >< res[2]
  )
  {
    version = UNKNOWN_VER;

    # Try to get version
    foreach file (files)
    {
      url = horde_dir + "/services/help/?module=kronolith&show=" + file;
      res = http_send_recv3(
        method       : "GET",
        item         : url,
        port         : port,
        exit_on_fail : TRUE
      );

      matches = egrep(pattern:file_pats[file], string:res[2]);
      if (matches)
      {
       foreach match (split(matches, keep:FALSE))
       {
         item = eregmatch(pattern:file_pats[file], string:match);
         if (!isnull(item))
         {
           version = item[1];
           break;
         }
       }
      }
    }

    installs = add_install(
      installs : installs,
      dir      : dir,
      appname  : "horde_kronolith",
      ver      : version,
      port     : port
    );
    if (!thorough_tests) break;
  }
}
if (max_index(keys(installs)) == 0) audit(AUDIT_WEB_APP_NOT_INST, "Kronolith", port);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : "Kronolith",
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
