#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58087);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/23 22:03:56 $");

  script_cve_id("CVE-2012-1190");
  script_osvdb_id(79392);

  script_name(english:"phpMyAdmin 3.4.x < 3.4.10.1 XSS (PMASA-2012-1)");
  script_summary(english:"Checks for unpatched JavaScript file");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of phpMyAdmin hosted on the remote web server is 3.4.x
prior to 3.4.10.1 and is reportedly affected by a cross-site scripting
vulnerability related to replication setup.");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2012-1.php");
  script_set_attribute(attribute:"solution", value:
"Apply the vendor patches or upgrade to phpMyAdmin version 3.4.10.1 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpMyAdmin", "www/PHP");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port    = get_http_port(default:80, php:TRUE);
install = get_install_from_kb(appname:"phpMyAdmin", port:port, exit_on_fail:TRUE);

dir = install['dir'];

url = dir + '/js/replication.js';
res = http_send_recv3(
  method : "GET",
  item   : url,
  port   : port,
  exit_on_fail : TRUE
);

if (
  '<br />log-bin=mysql-bin<br />log-error=mysql-bin.err<br />' >< res[2] &&
  '.html(' >< res[2]
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report = get_vuln_report(
      items   : make_list(url),
      trailer : 'The listed URL contains unpatched code that contributes to cross-site\n' +
                ' scripting vulnerabilities.',
      port    : port
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The phpMyAdmin install at "+build_url(port:port,qs:dir)+" is not affected.");
