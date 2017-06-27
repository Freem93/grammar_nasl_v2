#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(17689);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/01/14 20:12:25 $");

  script_cve_id("CVE-2005-0992");
  script_bugtraq_id(12982);
  script_osvdb_id(15226);

  script_name(english:"phpMyAdmin index.php convcharset Parameter XSS");
  script_summary(english:"Checks for convcharset cross-site scripting vulnerability in phpMyAdmin");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
cross-site scripting vulnerability." );
  script_set_attribute(attribute:"description", value:
"The installed version of phpMyAdmin suffers from a cross-site
scripting vulnerability due to its failure to sanitize user input to
the 'convcharset' parameter of the 'index.php' script.  A remote
attacker may use these vulnerabilities to cause arbitrary code to be
executed in a user's browser to steal authentication cookies and the
like." );
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin 2.6.2-rc1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/05");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/04");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("cross_site_scripting.nasl", "phpMyAdmin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpMyAdmin", "www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80, php:TRUE, no_xss:TRUE);

# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "');</script>";

# Test an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  # Try to exploit the vulnerability with our XSS.
  test_cgi_xss(port: port, cgi: "/index.php", dirs: make_list(dir),
 pass_str: xss, qs: string(
      "pma_username=&",
      "pma_password=&",
      "server=1&",
      "lang=en-iso-8859-1&",
      "convcharset=%5C%22%3E", urlencode(str:xss)
    ));
}
