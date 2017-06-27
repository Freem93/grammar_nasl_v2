#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56648);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"SonicWALL ViewPoint Server Detection");
  script_summary(english:"Looks for the SonicWALL ViewPoint login page");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A security appliance reporting application was detected on the remote
web server."
  );
  script_set_attribute(
    attribute:"description",
    value:
"SonicWALL ViewPoint Server reporting software was detected on the
remote host.  ViewPoint Server is a Windows-based software application
that utilizes a built-in web server to provide reporting functionality
for SonicWALL hardware and virtual appliances."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.sonicwall.com/lat/488_3036.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:sonicwall:viewpoint_server");
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
include("webapp_func.inc");
include("http.inc");

port = get_http_port(default:80);

# Loop through directories and include cgi if the "Perform thorough tests" setting is set.
if (thorough_tests) dirs = list_uniq(make_list("/sgms", cgi_dirs()));

# sgms is the default and is not easy to change
else dirs = make_list("/sgms");

installs = NULL;
foreach dir (dirs)
{
  # Request login
  url = dir + '/login';
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  # Make sure it's SonicWALL
  if ('SonicWALL' >< res[1] || 'SonicWALL' >< res[2])
  {
    pat = 'SonicWALL ViewPoint Version( |&nbsp;)([0-9.]+)';
    ver = NULL;

    # Iterate over res to extract the version
    # There should never be mixed versions
    foreach line (split(res[2], keep:FALSE))
    {
      z = eregmatch(string: line, pattern: pat, icase:TRUE);
      if (!isnull(z))
      {
        ver = z[2];
        break;
      }
    }

    if (dir == "") dir = "/";
    installs = add_install(
      appname  : "sonicwall_viewpoint",
      installs : installs,
      dir      : dir,
      ver      : ver,
      port     : port
    );

    # Scan for multiple installations only if "Thorough tests" is checked.
    if (!thorough_tests) break;
  }
}
if (isnull(installs))
  exit(0, "SonicWALL ViewPoint Server was not detected on the web server on port "+port+".");

# Report the findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : "SonicWALL ViewPoint Server",
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
