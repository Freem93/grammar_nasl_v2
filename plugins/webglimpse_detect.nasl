#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58411);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"WebGlimpse Detection");
  script_summary(english:"Looks for evidence of WebGlimpse");

  script_set_attribute(attribute:"synopsis", value:"The remote web server hosts a web-based site search application.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts WebGlimpse, a web-based site search
application."
  );
  script_set_attribute(attribute:"see_also", value:"http://webglimpse.net/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:webglimpse:webglimpse");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/cgi-bin/webglimpse", "/search", "/webglimpse", "/wg-cgi", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  url = strcat(dir, '/webglimpse.cgi');
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if (
    'WebGlimpse' >< res[2] &&
    (
      '<!-- Admins - "Use filters" must be checked for field-based searching,' >< res[2] ||
      '<OPTION VALUE="TITLE_AND_META">Title and Meta matches' >< res[2]
    )
  )
  {
    version = NULL;

    # Save info about the install.
    installs = add_install(
      appname  : "webglimpse",
      installs : installs,
      port     : port,
      dir      : dir,
      ver      : version
    );

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}
if (max_index(keys(installs)) == 0) exit(0, "WebGlimpse was not detected on the web server on port "+port+".");


# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    item         : '/webglimpse.cgi',
    display_name : "WebGlimpse"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
