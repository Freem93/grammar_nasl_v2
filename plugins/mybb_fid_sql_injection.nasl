#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19525);
  script_version ("$Revision: 1.23 $");
  script_cvs_date("$Date: 2017/02/23 16:41:17 $");

  script_cve_id("CVE-2005-2580", "CVE-2005-2697", "CVE-2005-2778");
  script_bugtraq_id(14553, 14615, 14684);
  script_osvdb_id(
    12798,
    19030,
    19031,
    19032,
    19033,
    19139
  );

  script_name(english:"MyBB <= 1.00 RC4 Multiple SQL Injection Vulnerabilities");
  script_summary(english:"Checks for multiple SQL injections in MyBB.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
multiple SQL injection vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MyBB installed on the remote host is affected by
multiple SQL injection vulnerabilities :
   

  - Multiple SQL injection vulnerabilities exist due to
    improper sanitization of user-supplied input passed via
    the 'Username' field, the 'action' parameter, and the
    'polloptions' parameter. A remote attacker can exploit
    this issue to manipulate SQL queries, resulting in the
    disclosure of sensitive information and modification of
    data. (CVE-2005-2580)

  - A SQL injection vulnerabilities exists due to improper
    sanitization of user-supplied input passed via the 'uid'
    parameter. A remote attacker can exploit this issue to
    manipulate SQL queries, resulting in the disclosure of
    sensitive information and modification of data.
    (CVE-2005-2697)

  - A SQL injection vulnerabilities exists due to improper
    sanitization of user-supplied input passed via the 'fid'
    parameter in the member.php script. A remote attacker
    can exploit this issue to manipulate SQL queries,
    resulting in the disclosure of sensitive information and
    modification of data. (CVE-2005-2778)

Note that the application is reportedly affected by several additional
SQL injection vulnerabilities. However, Nessus has not
tested for the additional vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/407960");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/408624");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/409523");
  script_set_attribute(attribute:"see_also", value:"http://community.mybboard.net/showthread.php?tid=3350");
  script_set_attribute(attribute:"solution", value:
"Apply the patch referenced in the vendor advisory. Alternatively,
enable PHP's 'magic_quotes_gpc' setting.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mybb:mybb");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");

  script_dependencie("mybb_detect.nasl");
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

exploits = make_list(
  "/polls.php?action=newpoll&tid=1&polloptions='" + script,
  "/search.php?action='" + script,
  "/search.php?action=finduser&uid=-1'" + script,
  "/member.php?action=profile&uid=lastposter&fid=-1'" + script
);

# Try to exploit the flaws.
foreach exploit (exploits)
{
  w = http_send_recv3(
    method : "GET",
    item   : dir + exploit,
    port   : port,
    exit_on_fail : TRUE
  );
  res = w[2];

  # There's a problem if we see a syntax error with our script name.
  if (
    egrep(
      string:res,
      pattern:"mySQL error: 1064<br>.+near '" +script+ "', ip=.+Query: UPDATE .*online SET uid="
    )
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
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
