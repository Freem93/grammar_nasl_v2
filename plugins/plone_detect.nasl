#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53545);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"Plone Detection");
  script_summary(english:"Checks for presence of Plone.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a content management system written in
Python."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running Plone, a free content management system
written in Python."
  );
  script_set_attribute(attribute:"see_also", value:"http://plone.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/25");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:plone:plone");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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

# By default, Zope serves on port 8080. However, most web servers are
# set up to proxy requests for certain directories to Zope, so we can
# just check port 80 and expect to catch most of them.
port = get_http_port(default:80);

# Put together a list of directories to search through.
if (thorough_tests)
  dirs = list_uniq(make_list("/plone", "/Plone", "/blog", "/cms", cgi_dirs()));
else
  dirs = make_list(cgi_dirs());

# Search for Plone.
installs = NULL;
foreach dir (dirs)
{
  # Try to access page.
  res = http_send_recv3(
    method       : "GET",
    item         : dir + "/",
    port         : port,
    exit_on_fail : TRUE
  );

  # Check the generator tag.
  if ('<meta name="generator" content="Plone - http://plone.org" />' >!< res[2])
    continue;

  # Parse path from URL.
  matches = eregmatch(string:res[2], pattern:'<a href="(?:https?://)?[^/]*(.*)/login(_form)?"');
  if (isnull(matches)) continue;

  # Ensure the canonical URL matches the directory we're currently
  # checking.
  if (dir != matches[1]) continue;

  # There is no good way to detect the version of Plone that is
  # running based on the web page itself.
  version = UNKNOWN_VER;

  installs = add_install(
    appname  : "plone",
    installs : installs,
    port     : port,
    dir      : dir,
    ver      : version
  );

  # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
  if (!thorough_tests) break;
}

if (isnull(installs)) exit(0, "Plone was not detected on the remote host.");

# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    display_name : "Plone"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
