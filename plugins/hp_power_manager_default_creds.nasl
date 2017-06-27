#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42832);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/18 20:40:53 $");

  script_name(english:"HP Power Manager Default Credentials");
  script_summary(english:"Attempts to log in with default credentials.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server is hosting a web application that uses default
login credentials."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running HP Power Manager, a web-based user definable
UPS management and monitoring utility.  The installed version has a
default password ('admin') set.  An attacker may connect to it to
reconfigure the application and control remote UPSs."
  );
  # http://h18000.www1.hp.com/products/servers/proliantstorage/power-protection/software/power-manager/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?386aa1fb");
  script_set_attribute(attribute:"solution", value:"Set a strong password for the 'admin' account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:hp:power_manager");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencies("hp_power_mgr_web_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80, embedded:TRUE);

install = get_install_from_kb(appname:'hp_power_mgr', port:port, exit_on_fail:TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);
dir = install['dir'];

login='admin';
pass='admin';

url = dir + '/goform/formLogin?Login=' + login + '&Password=' + pass;
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: TRUE);

if ("top.location.href = '/Contents/index.asp';" >< res[2])
{
  #Be sure this is HP Power Manager by following /Contents.index.asp
  #This doesn't work with follow_redirect because the original request
  #return HTTP/1.0  200 rather than 3xx
  res2 = http_send_recv3(method:"GET", item:"/Contents/index.asp", port:port);
  if (isnull(res2)) exit(1, "The web server on port "+port+" failed to respond.");

  if (
    "<title>HP Power Manager</title>" >< res2[2] &&
    "<frame name=head src=topFrame.html scrolling=no noresize>" >< res2[2] &&
    '<frame name="main" src="UPS/blank.asp" scrolling="auto" noresize>' >< res2[2]
  )
  {
    if (report_verbosity > 0)
    {
      report = get_vuln_report(items:url, port:port);
      security_hole(port:port, extra:report);
    }
    else security_hole(port:port);
  }
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "HP Power Manager", build_url(port:port, qs:dir+"/index.asp"));
