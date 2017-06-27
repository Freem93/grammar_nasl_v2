#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58232);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/21 20:57:10 $");

  script_name(english:"Tenable Appliance Web Authentication Bypass");
  script_summary(english:"Checks for the hotfix");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application running on the remote host has an authentication
bypass vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Tenable Appliance running on the remote host
has an authentication bypass vulnerability.

A remote, unauthenticated attacker could exploit this to gain
administrative access to the web interface."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Tenable Appliance 2.0.1 or later.

If upgrading is not possible, obtain the relevant hotfix from the
customer support portal and apply it to the appliance using the
'Update Appliance' section of the web interface's Administration page.

For version 1.0.3, use TenableApplianceHotfix_1.0.3.tar.gz.
For version 1.0.4 or 2.0.0, use TenableApplianceHotfix.tar.gz

Note that if a version of the appliance earlier than 1.0.3 is in use,
the hotfix cannot be applied and the system should be upgraded to the
latest version of the appliance."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/17");  # vulnerability first disclosed by this plugin
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/11"); # hotfix released
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:tenable:appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("tenable_appliance_web_detect.nasl");
  script_require_keys("www/tenable_appliance");
  script_require_ports("Services/www", 8000);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:8000);
install = get_install_from_kb(appname:'tenable_appliance', port:port, exit_on_fail:TRUE);

dir = install['dir'];
url = dir + '/password.ara';
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);
install_url = build_url(qs:'/', port:port);

headers = parse_http_headers(status_line:res[0], headers:res[1]);
if (isnull(headers)) exit(1, 'Error parsing HTTP headers on port '+port+'.');

http_code = headers['$code'];
if (http_code == 200)
{
  if (
    ('Communications with the Appliance' >< res[2]) &&
    ('Set Appliance Password' >< res[2])
  )
    security_hole(port);
  else
    audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Tenable Appliance', install_url);
}
else if (http_code == 303)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Tenable Appliance', install_url);
else
  audit(AUDIT_RESP_BAD, port, 'PoC (HTTP response code ' + http_code + ')');

