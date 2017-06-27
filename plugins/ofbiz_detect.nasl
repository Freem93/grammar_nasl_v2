#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59245);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/07/29 16:12:23 $");

  script_name(english:"Apache OFBiz Detection");
  script_summary(english:"Looks for OFBiz webapps");

  script_set_attribute(
    attribute:"synopsis",
    value:"A web application framework was detected on the remote web server."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Apache OFBiz is an open source enterprise resource planning (ERP)
system.  One or more web applications bundled with OFBiz were
detected on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://ofbiz.apache.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:open_for_business_project");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 8443);
  script_dependencies("http_version.nasl");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:8443);
login_page = '/control/checkLogin';
installs = make_list();

if (thorough_tests)
{
  webapps = make_array(
    'example', '<title>OFBiz[^<]+Example',
    'bi', '<title>OFBiz[^<]+Business Intelligence',
    'birt', '<title>OFBiz[^<]+Example',
    'partymgr', '<title>OFBiz[^<]+Party Manager',
    'content', '<title>OFBiz[^<]+Content Manager',
    'workeffort', '<title>OFBiz[^<]+WorkEffort Manager',
    'catalog', '<title>OFBiz[^<]+Catalog Manager',
    'facility', '<title>OFBiz[^<]+Facility Manager',
    'manufacturing', '<title>OFBiz[^<]+Manufacturing Manager',
    'accounting', '<title>OFBiz[^<]+Accounting Manager',
    'ar', '<title>OFBiz[^<]+AR Manager',
    'ap', '<title>OFBiz[^<]+AP Manager',
    'humanres', '<title>OFBiz[^<]+Human Resources Manager',
    'ordermgr', '<title>OFBiz[^<]+Order Manager',
    'marketing', '<title>OFBiz[^<]+Marketing Manager',
    'sfa', '<title>OFBiz[^<]+SFA Manager',
    'ofbizsetup', '<title>OFBiz[^<]+Setup Application',
    'ecommerce', 'Powered by <a href="http://ofbiz.apache.org"',
    'hhfacility', '<title>Hand Held Facility</title>',
    'assetmaint', '<title>OFBiz[^<]+Asset Maintenance',
    'ismgr', '<title>OFBiz[^<]+Is Manager',
    'ofbiz', '<a href="/ofbiz/control/forgotPassword(;jsessionid=[^"]+)?">Forgot Your Password',
    'projectmgr', '<title>OFBiz[^<]+Project',
    'oagis', '<title>OFBiz[^<]+Oagis',
    'googlebase', '<title>OFBiz',
    'googlecheckout', '<title>OFBiz[^<]+Google Checkout',
    'ebay', '<title>OFBiz',
    'ebaystore', 'Powered by <a href="http://ofbiz.apache.org"',
    'myportal', '<title>My Information',
    'webpos', 'Powered by <a href="http://ofbiz.apache.org"',
    'webtools', '<title>OFBiz[^<]+Web Tools'
  );
}
else
{
  webapps = make_array(
    'ordermgr', '<title>OFBiz[^<]+Order Manager',
    'ofbizsetup', '<title>OFBiz[^<]+Setup Application'
  );
}

foreach webapp (keys(webapps))
{
  dir = '/' + webapp;
  url = dir + login_page;
  pattern = webapps[webapp];

  res = http_send_recv3(method:'GET', port:port, item:url, exit_on_fail:TRUE);
  if (res[2] !~ pattern) continue;

  add_install(dir:dir, port:port, appname:'ofbiz_' + webapp); # save to KB, ignore return value
  installs = make_list(installs, url);
}

if (max_index(installs) == 0)
  audit(AUDIT_WEB_FILES_NOT, 'Apache OFBiz', port);

set_kb_item(name:'www/ofbiz/port', value:port);

if (report_verbosity > 0)
{
  report = '\nThe following OFBiz webapps were detected :\n\n';
  foreach install (sort(installs))
    report += build_url(qs:install, port:port) + '\n';

  if (!thorough_tests)
  {
    report +=
      '\nNessus did not attempt to detect all OFBiz webapps since the \'Thorough' +
      '\ntests\' setting was not enabled.\n';
  }

  security_note(port:port, extra:report);
}
else security_note(port);
