#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78082);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/04/25 14:31:38 $");

  script_cve_id("CVE-2014-3622");
  script_bugtraq_id(70259);

  script_name(english:"PHP 5.6.x < 5.6.1 'add_post_var' Code Execution");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by a code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP 5.6.x installed on the
remote host is prior to 5.6.1. It is, therefore, affected by errors
related to the function 'add_post_var' within file 'post_handler.c',
the input filters, and the 'efree' function. Input filters that free
the 'ksep' variable can also cause an improper 'efree' call. These
issues can allow arbitrary code execution.

Note that Nessus has not attempted to exploit these issues but has
instead relied only on application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://secure.php.net/ChangeLog-5.php#5.6.1");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 5.6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

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
if (version =~ "^5(\.6)?$") audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^5\.6\.") audit(AUDIT_NOT_DETECT, "PHP version 5.6.x", port);

if (
  # https://github.com/php/php-src/releases
  # only RC1 exists for 5.6.1; no alpha or beta.
  version =~ "^5\.6\.1-RC1($|[^0-9])" ||
  version =~ "^5\.6\.0($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : '+source +
      '\n  Installed version : '+version+
      '\n  Fixed version     : 5.6.1' + 
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
