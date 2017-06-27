#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65030);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/14 03:46:11 $");

  script_bugtraq_id(57012);
  script_osvdb_id(88551);

  script_name(english:"LogAnalyzer asktheoracle.php 'query' Parameter XSS");
  script_summary(english:"Attempts a non-persistent XSS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The LogAnalyzer install hosted on the remote web server is affected by
a cross-site scripting vulnerability due to a failure to properly
sanitize user input to the 'query' parameter of the 'asktheoracle.php'
script. An attacker can exploit this issue inject arbitrary HTML and
script code into a user's browser to be executed within the security
context of the affected site.");
  # http://loganalyzer.adiscon.com/news/loganalyzer-v3-6-1-v3-stable-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3cbd5a51");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Dec/146");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 3.6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adiscon:loganalyzer");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("loganalyzer_detect.nasl");
  script_require_keys("installed_sw/Adiscon LogAnalyzer");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

appname = "Adiscon LogAnalyzer";
get_install_count(app_name:appname, exit_if_zero:TRUE);

port    = get_http_port(default:80, php:TRUE);
install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);
dir     = install["path"];
version = install["version"];
url     = build_url(qs:dir+"/", port:port);

xss_test = '<script>alert("' + SCRIPT_NAME + '-' + unixtime() + '")</script>';
exploit = test_cgi_xss(
  port  : port,
  dirs  : make_list(dir),
  cgi   : '/asktheoracle.php',
  qs    : 'type=searchstr&query=' + urlencode(str:xss_test),
  pass_str :  xss_test,
  pass_re  : 'target="_blank">Adiscon'
);
if (!exploit) audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url);
