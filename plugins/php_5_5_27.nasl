#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84672);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/06/20 20:49:18 $");

  script_cve_id(
    "CVE-2015-3152",
    "CVE-2015-8838"
  );
  script_bugtraq_id(74398);
  script_osvdb_id(
    121459,
    124239,
    124412,
    124413,
    124414,
    137454
  );

  script_name(english:"PHP 5.5.x < 5.5.27 Multiple Vulnerabilities (BACKRONYM)");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP 5.5.x running on the
remote web server is prior to 5.5.27. It is, therefore, affected by
multiple vulnerabilities :

  - A security feature bypass vulnerability, known as
    'BACKRONYM', exists due to a failure to properly enforce
    the requirement of an SSL/TLS connection when the --ssl
    client option is used. A man-in-the-middle attacker can
    exploit this flaw to coerce the client to downgrade to
    an unencrypted connection, allowing the attacker to
    disclose data from the database or manipulate database
    queries. (CVE-2015-3152)

  - A flaw exists in the PHP Connector/C component due to a
    failure to properly enforce the requirement of an
    SSL/TLS connection when the --ssl client option is used.
    A man-in-the-middle attacker can exploit this to
    downgrade the connection to plain HTTP when HTTPS is
    expected. (CVE-2015-8838)

  - An unspecified flaw exists in the
    phar_convert_to_other() function in phar_object.c during
    the conversion of invalid TAR files. An attacker can
    exploit this flaw to crash a PHP application, resulting
    in a denial of service condition. (VulnDB 124239)

  - The '!' character is not treated as a special character
    when delayed variable substitution is enabled. The
    functions escapeshellcmd() and escapeshellarg() are
    unable to properly sanitize arguments containing '!'.
    An attacker can exploit this to execute arbitrary
    commands. (VulnDB 124412)

  - A double-free flaw exists in zend_vm_execute.h due to
    improper handling of certain code. An attacker can
    exploit this flaw to crash a PHP application, resulting
    in a denial of service condition. (VulnDB 124413)

  - A flaw exists in the parse_ini_file() and
    parse_ini_string() functions due to improper handling of
    strings that contain a line feed followed by an escape
    character. An attacker can exploit this to crash a PHP
    application, resulting in a denial of service condition.
    (VulnDB 124414)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.5.27");
  script_set_attribute(attribute:"see_also", value:"http://backronym.fail/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.5.27 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

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
if (version =~ "^5(\.5)?$") audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^5\.5\.") audit(AUDIT_NOT_DETECT, "PHP version 5.5.x", port);

if (version =~ "^5\.5\.([0-9]|1[0-9]|2[0-6])($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.5.27' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
