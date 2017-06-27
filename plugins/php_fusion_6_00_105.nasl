#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(19232);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/02/11 21:07:50 $");

  script_cve_id("CVE-2005-2074", "CVE-2005-2075");
  script_bugtraq_id(14066);
  script_osvdb_id(17610, 17611);

  script_name(english:"PHP-Fusion <= 6.00.105 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP-Fusion");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP application that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the remote host is running a version of
PHP-Fusion that is affected by multiple vulnerabilities :

  - An Information Disclosure Vulnerability
    PHP Fusion stores database backups in a known location
    within the web server's documents directory. An attacker
    may be able to retrieve these backups and obtain
    password hashes or other sensitive information from the
    database.

  - Multiple Cross-Site Scripting Vulnerabilities
    An attacker can inject malicious HTML and script code
    into the 'news_body', 'article_description', and the
    'article_body' parameters when submitting news or an
    article."
  );
  # http://packetstormsecurity.com/files/38299/Secunia-Security-Advisory-15830.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?575282e8");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP-Fusion 6.00.106 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/20");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php_fusion:php_fusion");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("php_fusion_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/php_fusion", "www/PHP");

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

# nb: 6.00.105 is known to be affected; other versions may also be.
if (ver =~ "^([0-5][.,]|6[.,]00[.,](0|10[0-5]))")
{
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "PHP-Fusion", build_url(qs:dir, port:port), ver);
