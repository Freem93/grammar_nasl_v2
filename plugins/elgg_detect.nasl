#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59655);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/06/22 21:30:01 $");

  script_name(english:"Elgg Detection");
  script_summary(english:"Looks for Elgg");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server is running a social networking engine written
in PHP."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running Elgg, a web-based social networking
engine written in PHP."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.elgg.org");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute: "plugin_publication_date", value:"2012/06/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elgg:elgg");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

if (thorough_tests) dirs = list_uniq(make_list("/elgg", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
meta_tag = '<meta name="ElggRelease" content="(.+)" />';

foreach dir (dirs)
{
  url = dir + '/index.php';
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if ('<div class="elgg-page-header">' >< res[2])
  {
    version = UNKNOWN_VER;

    # Try to get version
    matches = egrep(pattern:meta_tag, string:res[2]);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:meta_tag, string:match);
        if (!isnull(item))
        {
          version = item[1];
          break;
        }
      }
    }

    installs = add_install(
      installs : installs,
      dir      : dir,
      appname  : 'elgg',
      ver      : version,
      port     : port
    );
    if (!thorough_tests) break;
  }
}
if (max_index(keys(installs)) == 0) audit(AUDIT_NOT_INST, "Elgg");

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'Elgg',
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
