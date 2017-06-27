#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18054);
  script_version("$Revision: 1.14 $");

  script_name(english:"Serendipity Detection");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a blog application written in PHP." );
  script_set_attribute(attribute:"description", value:
"The remote host is running Serendipity, a PHP-based weblog / blog
software." );
  script_set_attribute(attribute:"see_also", value:"http://www.s9y.org/" );
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"solution", value:"n/a" );

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/15");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:s9y:serendipity");
  script_end_attributes();
 
  script_summary(english:"Checks for presence of Serendipity");
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");


port = get_http_port(default:80, php:TRUE);

# Search for Serendipity.
installs = make_array();

if (thorough_tests) dirs = list_uniq(make_list("/serendipity", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Grab index.php.
  res = http_send_recv3(
    port         : port,
    method       : "GET",
    item         : string(dir, "/index.php"), 
    exit_on_fail : TRUE
  );

  # Try to identify the version number from the Powered-By meta tag.
  if ('<meta name="Powered-By" content="Serendipity v' >< res[2]) {
    ver = UNKNOWN_VER;
    pat = 'meta name="Powered-By" content="Serendipity v\\.([^"]+)" />';
    matches = egrep(pattern:pat, string:res[2], icase:TRUE);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          ver = ver[1];
          break;
        }
      }
    }

    # Oh well, just mark it as "unknown".
    if (isnull(ver)) ver = UNKNOWN_VER;

    installs = add_install(
      installs : installs,
      dir      : dir,
      appname  : 'serendipity',
      ver      : ver,
      port     :port
    );

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}
if (max_index(keys(installs)) == 0) audit(AUDIT_NOT_INST, "Serendipity");

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'Serendipity',
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);

