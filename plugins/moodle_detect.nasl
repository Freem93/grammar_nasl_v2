#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18690);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"Moodle Detection");
  script_summary(english:"Detects Moodle.");

  script_set_attribute(attribute:"synopsis", value:"The remote web server hosts a course management system written in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Moodle, an open source course (or learning)
management system written in PHP.");
  script_set_attribute(attribute:"see_also", value:"http://moodle.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:moodle:moodle");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

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
include("install_func.inc");

port = get_http_port(default:80, php:TRUE);
app = "Moodle";

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/moodle", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs)
{
  # Request index.php.
  url = dir + '/index.php';
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  url_pattern = '<a [^>]*href="http://moodle\\.org/"[^>]*><img [^>]*src="[^>]*/moodlelogo(\\.gif)?"';
  # If it looks like Moodle...
  if (
    (
      egrep(pattern:'^Set-Cookie: *MoodleSession(Test)?=[a-zA-Z0-9]+;', string:res[1]) &&
      egrep(pattern:url_pattern, string:res[2])
    ) ||
    (
      egrep(pattern:'^Set-Cookie: *MOODLEID_=[%a-fA-F0-9]+;', string:res[1]) &&
      egrep(pattern:url_pattern, string:res[2])
    ) ||
    (
      'var moodleConfigFn = function' >< res[2] &&
      '<a href="#skipavailablecourses" class="skip-block">Skip available courses</a>' >< res[2]
    ) ||
    (
      '/help.php?module=moodle&amp;file=cookies.html&forcelang=' >< res[2] &&
      '<input type="hidden" name="testcookies" value="1"' >< res[2]
    ) ||
    egrep(pattern:url_pattern, string:res[2])
  )
  {
    version = NULL;

    # Try to extract the version number from the banner.
    pat = '<a title="moodle ([0-9][^"]+)" href="http://moodle\\.org/"';
    matches = egrep(pattern:pat, string:res[2], icase:TRUE);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:pat, string:match, icase:TRUE);
        if (!isnull(item))
        {
          version = item[1];
          break;
        }
      }
    }

    # If that didn't work, try to get it from the release notes.
    if (isnull(version))
    {
      url = dir + "/lang/en/docs/release.html";
      res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: 1);

      # nb: ignore patterns like "Moodle 1.5 (to be released shortly)"
      pat = "^<h2>Moodle (.+) \([0-9]";
      matches = egrep(pattern:pat, string:res[2], icase:TRUE);
      if (matches)
      {
        foreach match (split(matches, keep:FALSE))
        {
          item = eregmatch(pattern:pat, string:match, icase:TRUE);
          if (!isnull(item))
          {
            version = item[1];
            break;
          }
        }
      }
    }

    # Oh well, just mark it as "unknown".
    if (empty_or_null(version)) version = UNKNOWN_VER;

    installs++;

    register_install(
      app_name : app,
      port     : port,
      path     : dir,
      version  : version,
      cpe      : "cpe:/a:moodle:moodle",
      webapp   : TRUE
    );

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}
if (installs == 0) audit(AUDIT_WEB_APP_NOT_INST, app, port);

report_installs(port:port);
