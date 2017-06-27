#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65616);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/14 20:12:25 $");

  script_bugtraq_id(58226);
  script_osvdb_id(90708);

  script_name(english:"PHP-Fusion forum/viewthread.php highlight Parameter XSS");
  script_summary(english:"Attempts a non-persistent XSS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP script that is affected by a
cross-site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of PHP-Fusion installed on the remote host is affected by a
cross-site scripting vulnerability because it fails to properly sanitize
user input to the 'highlight' parameter of the 'forum/viewthread.php'
script.  An unauthenticated, remote attacker may be able to leverage
this to inject arbitrary HTML and script code into a user's browser to
be executed within the security context of the affected site. 

Note that successful exploitation requires that at least one forum
thread exists on the target install. 

Additionally, this version is also reportedly affected by SQL injection,
additional cross-site scripting, and local file inclusion
vulnerabilities as well as an information disclosure issue and an
arbitrary file deletion issue; however, Nessus did not test for these
additional issues."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.waraxe.us/advisory-97.html");
  script_set_attribute(attribute:"see_also", value:"http://www.php-fusion.co.uk/news.php?readmore=569");
  script_set_attribute(
    attribute:"solution",
    value:
"There is currently no known solution.  Version 7.02.06 reportedly
addresses multiple vulnerabilities; however, Tenable has confirmed the
cross-site scripting vulnerability in 'viewthread.php' in the 7.02.06
version."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php_fusion:php_fusion");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("php_fusion_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/php_fusion", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname:"php_fusion",
  port:port,
  exit_on_fail:TRUE
);

dir = install["dir"];
xss_test = "']);});alert(" + "'" + (SCRIPT_NAME - ".nasl")+ '-' + unixtime() +
           "'" + ');/*';
exploit = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : '/forum/viewthread.php',
  qs       : 'thread_id=1&highlight=' + urlencode(str:xss_test),
  pass_str : ".highlight(['" + xss_test,
  pass_re  : "Powered by \<a href='http://www.php-fusion.co.uk'\>PHP-Fusion"
);

if (!exploit)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "PHP-Fusion", build_url(qs:dir, port:port));
