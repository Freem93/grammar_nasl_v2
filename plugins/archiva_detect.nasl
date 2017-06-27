#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(54969);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/13 15:19:31 $");

  script_name(english:"Apache Archiva Detection");
  script_summary(english:"Looks for evidence of Apache Archiva Homepage");

  script_set_attribute(attribute:"synopsis", value:"The remote web server hosts a repository management application.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts Apache Archiva, an extensible repository
management tool for working with personal or enterprise-wide build
artifact repositories, such as those used with Maven, Continuum, and
ANT."
  );
  script_set_attribute(attribute:"see_also", value:"http://archiva.apache.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/05");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:archiva");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:8080, embedded:TRUE);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/archiva", "/repos", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  url = dir + '/index.action';
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if (
    (
      '<title>Apache Archiva \\' >< res[2] ||
      '<a target="_blank" href="http://archiva.apache.org/">Apache Archiva' >< res[2]
    ) &&
    'input type="hidden" name="completeQueryString"' >< res[2]
  )
  {
    version = NULL;

    pat = '<a [^>]+>Apache Archiva ([0-9]+\\.[^<]+)</a>';
    matches = egrep(pattern:pat, string:res[2]);
    if (matches)
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
    if (!version && '<div id="footer">' >< res[2])
    {
      footer = strstr(res[2], '<div id="footer">');
      footer = strstr(footer, '<div class="xleft">');
      footer = footer - strstr(footer, '</div>');

      foreach line (split(footer, keep:FALSE))
      {
        pat = '^ +Apache Archiva ([0-9]+\\..+)';
        item = eregmatch(pattern:pat, string:line);
        if (!isnull(item))
        {
          version = item[1];
          break;
        }
      }
    }

    installs = add_install(
      appname  : "archiva",
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
  exit(0, "Apache Archiva was not detected on the web server on port "+port+".");


# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    item         : '/index.action',
    display_name : "Apache Archiva"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
