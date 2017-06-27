#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57634);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/08 22:04:50 $");

  script_name(english:"SimpleSAMLphp Detection");
  script_summary(english:"Looks for a SimpleSAMLphp instance");

  script_set_attribute(attribute:"synopsis", value:"The remote web server hosts a PHP-based authentication application.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts SimpleSAMLphp, an implementation of SAML
(Security Assertion Markup Language) for written in PHP.  It acts as
both a Service Provider, authenticating users to PHP applications, as
well as an Identity Provider, storing information about them.");
  script_set_attribute(attribute:"see_also", value:"http://simplesamlphp.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/23");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:simplesamlphp:simplesamlphp");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

# Put together a list of directories we should check.
dirs = cgi_dirs();
if (thorough_tests)
  dirs = list_uniq(make_list("/simplesaml", "/saml", dirs));

# Put together checks for different pages that we can use to detect
# SimpleSAMLphp. Unfortunately, the version is not displayed anywhere.
checks = make_array();

regexes = make_list();
regexes[0] = make_list(
  '<title>simpleSAMLphp *installation *page</title>',
  'Copyright *&copy; *[-0-9]+ *<a +href="http://rnd.feide.no/">Feide *RnD</a>'
);
regexes[1] = make_list();
checks["/"] = regexes;

# Get the ports that webservers have been found on.
port = get_http_port(default:80, php:TRUE);

# Find where SimpleSAMLphp is installed.
installs = find_install(
  appname         : "simplesamlphp",
  checks          : checks,
  dirs		  : dirs,
  port		  : port,
  follow_redirect : 1
);

if (isnull(installs))
  exit(0, "SimpleSAMLphp was not detected on the web server on port " + port + ".");

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : "SimpleSAMLphp",
    installs     : installs,
    port         : port
  );
}
security_note(port:port, extra:report);
