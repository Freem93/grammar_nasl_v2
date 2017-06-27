#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53258);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/15 20:33:00 $");

  script_name(english:"Oracle BI Publisher Enterprise Detection");
  script_summary(english:"Looks for Oracle BI Publisher Enterprise");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server is running a report publishing application.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts Oracle BI Publisher Enterprise, a report
publishing system written in Java."
  );
  # http://www.oracle.com/technetwork/middleware/bi-publisher/overview/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ff02b8c");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 9704, 8888, 7001);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = 'Oracle BI Publisher';
port = get_http_port(default:9704);

ver_pat  = '<meta name=\"Generator\" content=\"Oracle BI Publisher ([0-9.]+) \\((build# [0-9.()]+)';

dirs = make_list('/xmlpserver');
if(thorough_tests) dirs = make_list(dirs, '/', cgi_dirs());

dirs = list_uniq(dirs);

installs = 0;
foreach dir (dirs)
{
  res = http_send_recv3(method:"GET", item:dir + '/', port:port, exit_on_fail:TRUE);

  if (
    '<title>Oracle BI Publisher Enterprise Login</title>' >< res[2] &&
    '<meta name="Generator" content="Oracle BI Publisher' >< res[2]
  )
  {
    matches = eregmatch(pattern:ver_pat, string:res[2], icase:FALSE);
    if (!isnull(matches))
    {
      ver   = matches[1];
      build = str_replace(string:matches[2], find:"#", replace:"");
      build = build - 'build ';

      register_install(
        app_name:appname,
        path:dir,
        port:port,
        version:ver,
        extra:make_array('Build', build),
        cpe:"cpe:/a:oracle:business_intelligence_publisher",
        webapp:TRUE
      );
      installs++;
      if (!thorough_tests) break;
    }
  }
}

if (installs == 0) audit(AUDIT_WEB_APP_NOT_INST, appname, port);
report_installs(port:port);
