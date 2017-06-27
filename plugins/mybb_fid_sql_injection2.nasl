#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19715);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2015/05/22 19:48:53 $");

  script_cve_id("CVE-2005-2888");
  script_bugtraq_id(14762);
  script_osvdb_id(19234, 19235);

  script_name(english:"MyBB misc.php Multiple SQL Injection Vulnerabilities");
  script_summary(english:"Checks for fid parameter SQL injection vulnerability in MyBB (2)."); 

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
multiple SQL injection vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MyBB installed on the remote host is affected by
multiple SQL injection vulnerabilities due to improper sanitization of
user-supplied input to the 'fid' parameter of the 'misc.php' script
and the 'Content-Disposition' field in the HTTP header to the
newreply.php script. A remote attacker can exploit these issues to
manipulate SQL queries, resulting in the disclosure of sensitive
information and modification of data.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/409743/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Enable PHP's 'magic_quotes_gpc' setting.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mybb:mybb");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

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

# Try to exploit the flaws.
w = http_send_recv3(
  method :"GET",
  item   : dir + "/misc.php?action=rules&fid=-1'" + script, 
  port   : port,
  exit_on_fail : TRUE
);
res = w[2];

# There's a problem if we see a syntax error with our script name.
if (
  egrep(
    string:res,
    pattern:"mySQL error: 1064<br>.+near '" +script+ "' .+Query: SELECT \\* FROM .*forums")
)
{
  output = strstr(res, "mySQL error: 1064");
  if (empty_or_null(output)) output = res;

  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    generic    : TRUE,
    sqli       : TRUE,  # Sets SQLInjection KB key
    request    : make_list(http_last_sent_request()),
    output     : chomp(output)
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
