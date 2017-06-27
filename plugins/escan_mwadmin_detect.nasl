#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45344);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/09 00:11:22 $");

  script_name(english:"eScan MWAdmin Interface Detection");
  script_summary(english:"Looks for the eScan admin login page");

  script_set_attribute(attribute:"synopsis", value:"A web-based antivirus interface was detected on the remote host.");
  script_set_attribute(
    attribute:"description",
    value:
"MWAdmin, a web interface included with multiple Linux-based eScan
products, was detected on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.escanav.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 10080);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:10080, php:TRUE);

dir = '';
url = dir + '/index.php';
res = http_get_cache(item:url, port:port, exit_on_fail:TRUE);

if ('<TITLE>eScan Anti-virus Admin</TITLE>' >< res)
{
  installs = add_install(
    installs:installs,
    dir:dir,
    appname:'escan_mwadmin',
    port:port
  );

  if (report_verbosity > 0)
  {
    report = get_install_report(
      display_name:'eScan MWAdmin',
      installs:installs,
      port:port
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else exit(0, 'eScan MWAdmin wasn\'t detected on port '+port+'.');

