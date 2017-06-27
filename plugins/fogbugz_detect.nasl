#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38156);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/02/07 18:43:41 $");

  script_name(english:"FogBugz Interface Detection");
  script_summary(english:"Detects FogBugz Web Interface");

  script_set_attribute(attribute:"synopsis", value:"The remote web server contains a project management software");
  script_set_attribute(attribute:"description", value:
"The remote web server is running the web interface for FogBugz, a web
interface for a project management software

As this interface is likely to contain sensitive information, make
sure only authorized personel can log into this site");
  script_set_attribute(attribute:"see_also", value:"http://www.fogcreek.com/Fogbugz/");
  script_set_attribute(attribute:"solution", value:"Make sure the proper access controls are put in place");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fog_creek_software:fogbugz");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
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

dirs = make_list("", "/fogbugz");
foreach dir (dirs)
{
  url = dir + "/default.php";
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  line = egrep(pattern:'<a href="http://www\\.fogcreek\\.com/FogBugz">FogBugz</a> Version', string:res[2]);
  if (line)
  {
    version = ereg_replace(
      pattern:".*FogBugz</a> Version&nbsp;([0-9.]+)&nbsp;\(.*Build ([0-9]+).*", 
      replace:"\1 (Build \2)",
      string:line
    );
    register_install(
      app_name : 'FogBugz',
      path     : dir,
      port     : port,
      version  : version,
      cpe      : "cpe:/a:fog_creek_software:fogbugz",
      webapp   : TRUE
    );
    report_installs(port:port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_INST, "FogBugz", port);
