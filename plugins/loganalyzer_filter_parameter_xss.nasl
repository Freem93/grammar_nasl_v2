#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62123);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/14 03:46:11 $");

  script_bugtraq_id(53664);
  script_osvdb_id(82137);

  script_name(english:"LogAnalyzer index.php 'filter' Parameter XSS");
  script_summary(english:"Attempts a non-persistent XSS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The LogAnalyzer install hosted on the remote web server is affected by
a cross-site scripting vulnerability due to a failure to properly
sanitize user input to the 'filter' parameter of the 'index.php'
script. An attacker can exploit this issue to inject arbitrary HTML
and script code into a user's browser to be executed within the
security context of the affected site.

The application is reportedly also affected by a SQL injection
vulnerability, an arbitrary file read vulnerability, and additional
cross-site scripting vulnerabilities; however, Nessus has not tested
for these additional vulnerabilities.");
  # http://www.codseq.it/advisories/multiple_vulnerabilities_in_loganalyzer
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f9d105f");
  # http://loganalyzer.adiscon.com/downloads/loganalyzer-3-4-3-v3-stable
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6da2d063");
  # http://loganalyzer.adiscon.com/news/loganalyzer-v3-5-4-v3-beta-released
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?07a25948");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 3.4.3 / 3.5.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adiscon:loganalyzer");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

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

xss_test = '</title><script>alert(' + "'" + SCRIPT_NAME + '-' + unixtime() + "'" + ');</script>';

exploit = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : '/index.php',
  qs       : 'filter=' + urlencode(str:xss_test),
  pass_str : "Results for the search '" + xss_test,
  pass_re  : 'target="_blank">Adiscon LogAnalyzer'
);

if (!exploit) audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url);
