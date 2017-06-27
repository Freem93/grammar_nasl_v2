#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(19311);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2015/01/14 20:12:25 $");

  script_cve_id("CVE-2005-2401", "CVE-2005-3159");
  script_bugtraq_id(14332, 14489);
  script_osvdb_id(18111, 18708);

  script_name(english:"PHP-Fusion <= 6.00.106 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP-Fusion");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts an application that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the remote host is running a version of
PHP-Fusion that suffers from multiple vulnerabilities :

  - SQL Injection Vulnerability
    The application fails to sanitize user-supplied input to the
    'msg_view' parameter of the 'messages.php' script before
    using it in database queries. Exploitation requires that an
    attacker first authenticate and that PHP's 'magic_quotes_gpc'
    be disabled.

  - HTML Injection Vulnerability
    An attacker can inject malicious CSS (Cascading Style Sheets)
    codes through [color] tags, thereby affecting how the site is
    rendered whenever users view specially crafted posts."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.php-fusion.co.uk/news.php?readmore=244" );
  script_set_attribute(attribute:"see_also", value:"http://www.php-fusion.co.uk/news.php?readmore=247" );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to PHP-Fusion 6.00.107 or later or apply the patches in the
vendor's advisories referenced above."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php_fusion:php_fusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("php_fusion_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/php_fusion");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:80, php:TRUE);

# Test an install.
install = get_install_from_kb(
  appname      : "php_fusion",
  port         : port,
  exit_on_fail : TRUE
);
dir = install["dir"];
ver = install["ver"];

if (ver =~ "^([45][.,]|6[.,]00[.,](0|10[0-6]))")
{
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "PHP-Fusion", build_url(qs:dir, port:port), ver);
