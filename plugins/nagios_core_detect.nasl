#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63562);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/01/17 01:04:12 $");

  script_name(english:"Nagios Core Detection");
  script_summary(english:"Detects Nagios Core web interface");

  script_set_attribute(
    attribute:"synopsis",
    value:"A monitoring service is running on the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The web interface for Nagios Core was detected on the remote host. 
Nagios Core is a web-based application for monitoring network devices."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nagios.org/projects/nagioscore");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nagios:nagios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

appname = "Nagios Core";
kb_appname = "nagios_core";

# Loop through various directories.
if (thorough_tests) dirs = make_list("/nagios", cgi_dirs());
else dirs = make_list(cgi_dirs());

installs = NULL;
foreach dir (list_uniq(dirs))
{
  res = http_send_recv3(
    method:'GET',
    item:dir + '/main.php',
    port:port,
    exit_on_fail:TRUE
  );

  if (
    "<title>Nagios Core</title>" >< res[2] && 
    "<h2>Get Started</h2>" >< res[2]
  )
  {
    version = UNKNOWN_VER;
    item = eregmatch(pattern:'\"version\">[ ]*Version[ ]+([^<]+)', string:res[2]);  
    if (!isnull(item[1])) version = item[1];
    
    # Register install
    installs = add_install(
      installs:installs,
      ver:version,
      dir:dir,
      appname:kb_appname,
      port:port
    );
    if (!thorough_tests) break;
  }
}

if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, appname, port);

# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    display_name : appname,
    item         : '/' 
  );
  security_note(port:port, extra:report);
}
else security_note(port);
