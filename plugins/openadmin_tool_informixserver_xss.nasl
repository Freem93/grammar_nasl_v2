#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56172);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/02 14:37:07 $");

  script_cve_id("CVE-2011-3390");
  script_bugtraq_id(49364);
  script_osvdb_id(75214);

  script_name(english:"OpenAdmin Tool for Informix informixserver Parameter XSS");
  script_summary(english:"Tries to inject script code via the 'informixserver' parameter");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is prone to a cross-
site scripting attack.");
  script_set_attribute(attribute:"description", value:
"The instance of OpenAdmin Tool for Informix hosted on the remote web
server fails to sanitize user input to the 'informixserver' parameter
of its 'index.php' script before using it to generate dynamic HTML
output.

An attacker may be able to leverage this issue to inject arbitrary
HTML or script code into a user's browser to be executed within the
security context of the affected site.

Note that this script is likely affected by other cross-site scripting
issues involving the 'host' and 'port' parameters as well, although
Nessus has not checked for them.");
  script_set_attribute(attribute:"see_also", value:"http://voidroot.blogspot.com/2011/08/xss-in-ibm-open-admin-tool.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Aug/203");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenAdmin Tool version 2.72 or later as that reportedly
fixes the vulnerability.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:openadmin_tool");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("openadmin_tool_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP", "www/openadmin");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:8080);


# Test an install.
install = get_install_from_kb(appname:'openadmin_tool', port:port, exit_on_fail:TRUE);
dir = install['dir'];


# Try to exploit the issue.
alert = "<script>alert('" + SCRIPT_NAME + "')</script>";
exploit = unixtime() + '">' + alert;

vuln = test_cgi_xss(
  port     : port,
  cgi      : '/index.php',
  dirs     : make_list(dir),
  qs       : "act=login&" +
             "do=dologin&" +
             "login_admin=Login&" +
             "groups=1&" +
             "grouppass=&" +
             "informixserver=" + urlencode(str:exploit) + "&" +
             "host=&" +
             "port=&" +
             "username=&" +
             "userpass=&" +
             "idsprotocol=onsoctcp&" +
             "conn_num=",
  pass_str : 'name="informixserver" value="' + exploit + '"/>',
  pass2_re : '(popAboutOAT|OAT Group)'
);

if (!vuln)
  exit(0, "The OpenAdmin Tool install at "+build_url(port:port, qs:dir+'/')+" is not affected.");
