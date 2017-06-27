#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51456);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"PhpGedView Detection");
  script_summary(english:"Looks at initial page");

  script_set_attribute(attribute:"synopsis", value:"The remote web server hosts a genealogy program.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts PhpGedView, an open source genealogy
program written in PHP."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.phpgedview.net/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpgedview:phpgedview");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php:TRUE, embedded:FALSE);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/phpgedview", "/PhpGedView", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  url = dir + '/login.php?url=editgedcoms.php';
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if (
    'meta name="generator" content="PhpGedView' >< res[2] ||
    '<title>PhpGedView User Login - PhpGedView</title>' >< res[2] ||
    '<script src="js/phpgedview.js"' >< res[2]
  )
  {
    version = NULL;

    url = dir + "/changelog.txt";
    res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

    pat = '^Version +([0-9]+\\..+)$';
    matches = egrep(pattern:pat, string:res[2]);
    if (
      "Change Log" >< res[2] &&
      "www.phpgedview.net" >< res[2] &&
      matches
    )
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          version = item[1];
          break;
        }
      }
    }

    installs = add_install(
      appname  : "phpgedview",
      installs : installs,
      port     : port,
      dir      : dir,
      ver      : version
    );

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}
if (isnull(installs))
  exit(0, "PhpGedView was not detected on the web server on port "+port+".");


# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    display_name : "PhpGedView"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
