#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61430);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_bugtraq_id(51069);
  script_osvdb_id(77763);

  script_name(english:"Nagios XI < 2011R1.9 login.php XSS");
  script_summary(english:"Attempts a reflective XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Nagios XI hosted on the remote web server fails to
properly sanitize input to the login.php script. 

An attacker can leverage this issue by enticing a user to follow a
malicious URL, causing attacker-specified script code to run inside
the user's browser in the context of the affected site. Information
harvested this way may aid in launching further attacks.");
  script_set_attribute(attribute:"solution", value:"Upgrade to Nagios XI 2011R1.9 build 20111213 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"see_also", value:"http://assets.nagios.com/downloads/nagiosxi/CHANGES-2011.TXT");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/520875/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://0a29.blogspot.ca/2011/12/0a29-11-3-cross-site-scripting.html");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nagios:nagios");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("nagios_enterprise_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/nagios_xi");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

# Get the ports that web servers have been found on.
port = get_http_port(default:80);

# Get details of the install.
install = get_install_from_kb(appname:"nagios_xi", port:port, exit_on_fail:TRUE);
dir = install["dir"];

cgi = "/login.php";
xss = '/";alert(\'' + SCRIPT_NAME + '-' + unixtime() + '\');"';

xss_re = xss;
xss_re = str_replace(string:xss_re, find:"(", replace:"\(");
xss_re = str_replace(string:xss_re, find:")", replace:"\)");

exploited = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : cgi,
  qs       : xss,
  no_qm    : TRUE,
  pass_re  : 'var backend_url="[^"]+' + dir + cgi + xss_re + '";',
  ctrl_re  : "<!-- Produced by Nagios XI"
);

if (!exploited)  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Nagios XI", build_url(qs:dir + cgi, port:port));
