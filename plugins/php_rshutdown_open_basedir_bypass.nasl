#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73289);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2012-1171");
  script_bugtraq_id(65673);
  script_osvdb_id(104201);

  script_name(english:"PHP PHP_RSHUTDOWN_FUNCTION Security Bypass");
  script_summary(english:"Checks version of PHP");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is potentially
affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP 5.x installed on the
remote host is 5.x prior to 5.3.11 or 5.4.x prior to 5.4.1 and thus,
is potentially affected by a security bypass vulnerability.

An error exists related to the function 'PHP_RSHUTDOWN_FUNCTION' in
the libxml extension and the 'stream_close' method that could allow a
remote attacker to bypass 'open_basedir' protections and obtain
sensitive information.

Note that this plugin has not attempted to exploit this issue, but has
instead relied only on PHP's self-reported version number.");
  # https://github.com/php/php-src/commit/167e2fd78224887144496cdec2089cd5b2f3312d
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bcc428c2");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=61367");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 5.3.11 / 5.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

version = php["ver"];
source = php["src"];

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

# Check that it is the correct version of PHP
if (version =~ "^5(\.[34])?$") audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^5\.[01234]($|[^0-9])") audit(AUDIT_NOT_DETECT, "PHP version 5.0.x - 5.4.x", port);

# Affected
# 5.0.x through 5.2.x
# 5.3.x < 5.3.11
# 5.4.x < 5.4.1
if (
  version =~ "^5\.[012]($|[^0-9])" ||
  version =~ "^5\.3\.([0-9]|10)($|[^0-9])" ||
  version =~ "^5\.4\.0($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : '+source +
      '\n  Installed version : '+version+
      '\n  Fixed version     : 5.3.11 / 5.4.1\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
