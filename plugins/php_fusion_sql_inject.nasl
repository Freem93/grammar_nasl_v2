#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15433);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_cve_id("CVE-2004-2437", "CVE-2004-2438");
  script_bugtraq_id(11296, 12425);
  script_osvdb_id(10437, 10438, 10439);

  script_name(english:"PHP-Fusion 4.01 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PHP-Fusion");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts multiple PHP scripts that are affected
by multiple flaws."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability exists in the version of PHP-Fusion installed on
the remote host that may allow an authenticated attacker to inject
arbitrary SQL code due to improper validation of user-supplied input
to the 'rowstart' parameter of script 'members.php' and the
'comment_id' parameter of the 'comments.php' script.

Additionally, the version of this software also contains several
cross-site scripting issues as well as an information disclosure
vulnerability; however, Nessus has not tested for these issues."
  );
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/08");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php_fusion:php_fusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

  script_dependencie("php_fusion_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/php_fusion");

  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname      : "php_fusion",
  port         : port,
  exit_on_fail : TRUE
);
dir = install["dir"];
version = install["ver"];

if (ereg(pattern:"^([0-3][.,]|4[.,]0[01]([^0-9]|$))", string:version))
{
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "PHP-Fusion", build_url(qs:dir, port:port), version);
