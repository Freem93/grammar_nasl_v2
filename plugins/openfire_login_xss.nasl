#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51143);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/14 20:12:25 $");

  script_name(english:"Openfire Admin Console login.jsp XSS");
  script_summary(english:"Attempts reflected XSS");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host has a cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Openfire admin console running on the remote host has a cross-site
scripting vulnerability. Input to the 'username' parameter of
'login.jsp' is not properly sanitized.

An attacker could exploit this by tricking a user into making a
specially crafted POST request, resulting in arbitrary script
execution in the user's browser.

This version of Openfire likely has other vulnerabilities, though
Nessus has not checked for those issues.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22eb6a7f");
  script_set_attribute(attribute:"solution", value:"Upgrade to Openfire 3.7.0 beta or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:igniterealtime:openfire");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("openfire_console_detect.nasl");
  script_require_ports("Services/www", 9090);
  script_require_keys("www/openfire_console");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");


port = get_http_port(default:9090);
install = get_install_from_kb(appname:'openfire_console', port:port, exit_on_fail:TRUE);

url = install['dir'] + '/login.jsp';
xss = '" onmouseover="javascript:alert(\'' + SCRIPT_NAME + '-' + unixtime() + '\');';
xss_encoded = urlencode(str:xss);
data = 'login=true&username=' + xss_encoded + '&password=';
res = http_send_recv3(
  method:'POST',
  item:url,
  port:port,
  data:data,
  content_type:'application/x-www-form-urlencoded',
  exit_on_fail:TRUE
);

if ('value="' + xss + '">' >< res[2])
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report = '\nNessus verified the issue using the following request :\n\n' + http_last_sent_request();
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else
{
  base_url = build_url(qs:install['dir'], port:port);
  exit(0, 'The Openfire admin console at '+base_url+' is not affected.');
}

