#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(21239);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/05/22 19:48:53 $");

  script_cve_id("CVE-2006-1912");
  script_bugtraq_id(17564);
  script_osvdb_id(24710, 24711);
  

  script_name(english:"MyBB global.php 'KILL_GLOBAL' Overwrite SQL Injection");
  script_summary(english:"Tests a SQL injection flaw.");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by a
global variable overwrite vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MyBB installed on the remote host is affected by
a global variable overwrite vulnerability due to a failure to properly
initialize global variables in the global.php script. A remote,
unauthenticated attacker can exploit this issue to overwrite global
variables to launch a SQL injection attack against the application,
as well as other attacks using GET or POST HTTP requests.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/431061/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://community.mybboard.net/showthread.php?tid=8232");
  script_set_attribute(attribute:"solution", value:"Upgrade to MyBB 1.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/04/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mybb:mybb");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("mybb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "installed_sw/MyBB");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "MyBB";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

script = SCRIPT_NAME;
url = "/global.php?_SERVER[HTTP_CLIENT_IP]='" + script;

# Try to exploit the flaw to generate a SQL syntax error.
w = http_send_recv3(
  method : "GET", 
  item   : dir + url,
  port   : port,
  exit_on_fail : TRUE
);
res = w[2];

# There's a problem if we see a syntax error with our script name.
if (egrep(
  pattern:"mySQL error: 1064.+near '" + script+ "''.+Query: SELECT sid,uid",
  string:res)
)
{
  output = strstr(res, "mySQL error: 1064");
  if (empty_or_null(output)) output = res;

  security_report_v4(
    port       : port,
    severity   : SECURITY_WARNING,
    generic    : TRUE,
    sqli       : TRUE,  # Sets SQLInjection KB key
    request    : make_list(http_last_sent_request()),
    output     : chomp(output)
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
