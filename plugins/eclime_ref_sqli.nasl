#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51141);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/20 13:54:16 $");

  script_cve_id("CVE-2010-4851");
  script_bugtraq_id(45124);
  script_osvdb_id(69603);
  script_xref(name:"EDB-ID", value:"15644");

  script_name(english:"eclime index.php ref Parameter SQL Injection");
  script_summary(english:"Tries to generate a SQL error");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that is susceptible to a
SQL injection attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of eclime hosted on the remote web server fails to
sanitize input to the 'ref' parameter of the 'index.php' script before
using it in a database query.

Regardless of PHP's 'magic_quotes_gpc' setting, an unauthenticated
remote attacker can leverage this issue to manipulate SQL queries and
potentially uncover sensitive information from the associated
database, read arbitrary files, or execute arbitrary PHP code."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.htbridge.ch/advisory/sql_injection_in_eclime_1.html");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("oscommerce_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/eclime");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php:TRUE);


install = get_install_from_kb(appname:'eclime', port:port, exit_on_fail:TRUE);
dir = install['dir'];
install_url = build_url(port:port, qs:dir+"/");


# Try to exploit the issue to generate a SQL error.
magic1 = "-1" + rand() % 1000;
magic2 = SCRIPT_NAME;

exploit = magic1 + "%27 " + magic2 + " -- %27";
url = dir + '/?' +
  'ref=' + str_replace(find:" ", replace:"%20", string:exploit);

res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

if (
  '[TEP STOP]</font>' >< res[2] &&
  "banners_affiliate_id = '"+magic1+"' "+magic2 >< res[2]
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report = '\n' +
      'Nessus was able to verify the issue by manipulating the database\n' +
      'query and generating a SQL error using the following URL :\n' +
      '\n' +
      '  ' + build_url(port:port, qs:url) + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The eclime install at "+install_url+" is not affected.");
