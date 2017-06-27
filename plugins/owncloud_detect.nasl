#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59727);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/07/09 16:36:52 $");

  script_name(english:"ownCloud Web Interface Detection");
  script_summary(english:"Detects ownCloud's login page");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is running a web-based cloud storage software suite."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running ownCloud, a web-based PHP cloud storage
software suite."
  );
  script_set_attribute(
    attribute:"solution",
    value:"n/a"
  );
  script_set_attribute(attribute:"risk_factor",value:"None");
  script_set_attribute(attribute:"plugin_publication_date",value:"2012/06/27");
  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:owncloud:owncloud");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
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

appname = "ownCloud";
port = get_http_port(default:80, php:TRUE);

dirs = list_uniq(make_list("/owncloud", "/ownCloud", cgi_dirs()));
dirs = list_uniq(dirs);

installs = NULL; 

foreach dir (dirs)
{
  url = dir + '/index.php';
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
  # detect ownCloud login page
  if("<title>ownCloud</title>" >< res[2] &&
     ">Username<" >< res[2] && ">Password<" >< res[2])
  { 
    version = "unknown";

    # Try to obtain version
    res = http_send_recv3(
            method:'GET',
            item:dir+'/status.php', 
            port:port, 
            exit_on_fail:TRUE
          );

    item = eregmatch(pattern:'"version":"([0-9\\.]+)"', string:res[2]);
    if(!isnull(item[1]))
      version = item[1];

    installs = add_install(
      installs:installs,
      dir:dir,
      ver:version,
      appname:'owncloud',
      port:port
    );

    if (!thorough_tests) break;
  }
}

if (isnull(installs))
  audit(AUDIT_NOT_DETECT, appname, port);

if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    item         : '/index.php',
    display_name : appname
  );
  security_note(port:port, extra:report);
}
else security_note(port);

exit(0);
