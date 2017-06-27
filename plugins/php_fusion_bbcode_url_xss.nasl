#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(19597);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/01/14 20:12:25 $");

  script_cve_id("CVE-2005-2783");
  script_bugtraq_id(14688);
  script_osvdb_id(19072);

  script_name(english:"PHP-Fusion < 6.00.108 BBCode Nested URL Tag XSS");
  script_summary(english:"Checks the version of PHP-Fusion");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP script that is prone to
cross-site scripting attacks."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version number, the remote host is running a version
of PHP-Fusion that reportedly does not sufficiently sanitize input
passed in nested 'url' BBcode tags before using it in a post.  An
attacker may be able to exploit this flaw to cause arbitrary script
and HTML code to be executed in the context of a user's browser when
viewing the malicious BBcode on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/409490" );
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP-Fusion 6.00.108 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/08");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php_fusion:php_fusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

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

if (ver =~ "^([45][.,]|6[.,]00[.,](0|10[0-7]))") {
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "PHP-Fusion", build_url(qs:dir, port:port), ver);

