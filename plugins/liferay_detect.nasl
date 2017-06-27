#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59228);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/04/15 18:50:56 $");

  script_name(english:"Liferay Portal Detection");
  script_summary(english:"Looks at server headers and for a login page");

  script_set_attribute(attribute:"synopsis", value:"A Java-based web portal is installed on the remote host.");
  script_set_attribute(attribute:"description", value:"Liferay Portal, a Java web portal, is installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.liferay.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/22");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:liferay:portal");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 443, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

# Get the ports that web servers have been found on, defaulting to
# what Liferay uses with Tomcat, their recommended bundle.
port = get_http_port(default:8080);

# Put together a list of directories we should check for Liferay in.
dirs = list_uniq(make_list("", cgi_dirs()));

installs = NULL;
foreach dir (dirs)
{
  res = http_send_recv3(
    method          : "GET",
    item            : dir + "/",
    port            : port,
    follow_redirect : 1,
    exit_on_fail    : TRUE
  );
  if ("Liferay-Portal:" >!< res[1]) continue;

  # page not found, only report valid index pages
  if ("404" >< res[0])
    continue;

  # Extract the version information from the response headers using build.
  regex = "Liferay-Portal: *Liferay *Portal.*(Build (\d+))";
  matches = eregmatch(string:res[1], pattern:regex);
  if (isnull(matches)) continue;

  build = matches[2];

  # Convert the build to our expected version format
  version = "";

  # The maintence release can be two digits if/else to compensate for it
  if (build[2] == 0)
  {
    build -= '0';
    for (i = 0; i < strlen(build); i++) version += '.' + build[i];
    version -= '.';
  }
  else
  {
     for (i = 0; i < strlen(build)-2; i++) version += build[i] + '.';
     version += build[strlen(build)-2] + build[strlen(build)-1];
  }

  # Register the installed instance.
  installs = add_install(
    installs : installs,
    port     : port,
    dir      : dir,
    appname  : "liferay_portal",
    ver      : version
  );

  # Only continue looking for additional installations if we're being
  # thorough.
  if (!thorough_tests) break;
}

if (isnull(installs)) audit(AUDIT_NOT_DETECT, "Liferay Portal", port);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : "Liferay Portal",
    installs     : installs,
    port         : port
  );
}

security_note(port:port, extra:report);
