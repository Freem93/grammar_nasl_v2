#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51425);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/20 14:30:35 $");

  script_cve_id("CVE-2010-4480");
  script_bugtraq_id(45633);
  script_osvdb_id(69684);
  script_xref(name:"EDB-ID", value:"15699");

  script_name(english:"phpMyAdmin error.php BBcode Tag XSS (PMASA-2010-9)");
  script_summary(english:"Tries to inject HTML");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP script that is prone to a cross-
site scripting attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of phpMyAdmin fails to validate BBcode tags in user input
to the 'error' parameter of the 'error.php' script before using it to
generate dynamic HTML.

An attacker may be able to leverage this issue to inject arbitrary
HTML or script code into a user's browser to be executed within the
security context of the affected site.  For example, this could be
used to cause a page with arbitrary text and a link to an external
site to be displayed."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2010-9.php");
  script_set_attribute(attribute:"solution", value:"Upgrade to phpMyAdmin 3.4.0-beta1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/phpMyAdmin", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php:TRUE, embedded:FALSE);


install = get_install_from_kb(appname:"phpMyAdmin", port:port, exit_on_fail:TRUE);
dir = install['dir'];


# Try to exploit the issue.
link = 'http://www.phpmyadmin.net/home_page/security/PMASA-2010-9.php';
text = 'Click here';
payload = '[a@' + link + '@_self]' + text + '[/a]';

vuln = test_cgi_xss(
  port     : port,
  cgi      : '/error.php',
  dirs     : make_list(dir),
  qs       : 'type='+SCRIPT_NAME+'&error='+urlencode(str:payload),
  pass_str : 'phpMyAdmin',
  pass2_re : '<a href="' + link + '" target="_self">' + text + '</a></p>'
);
if (!vuln) exit(0, "The phpMyAdmin install at "+build_url(port:port, qs:dir+'/')+" is not affected.");
