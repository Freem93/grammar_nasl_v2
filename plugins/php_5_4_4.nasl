#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59530);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2013/12/04 16:28:14 $");

  script_cve_id("CVE-2012-2143", "CVE-2012-2386", "CVE-2012-3450");
  script_bugtraq_id(47545, 53729, 54777);
  script_osvdb_id(72399, 82510, 82931);
  script_xref(name:"EDB-ID", value:"17201");

  script_name(english:"PHP 5.4.x < 5.4.4 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of PHP installed on the remote
host is 5.4.x earlier than 5.4.4, and as such is potentially
affected the following vulnerabilities :

  - An integer overflow error exists in the function
    'phar_parse_tarfile' in the file 'ext/phar/tar.c'. This
    error can lead to a heap-based buffer overflow when
    handling a maliciously crafted TAR files. Arbitrary code
    execution is possible due to this error. (CVE-2012-2386)

  - A weakness exists in the 'crypt' function related to
    the DES implementation that can allow brute-force
    attacks. (CVE-2012-2143)

  - Several design errors involving the incorrect parsing
    of PHP PDO prepared statements could lead to disclosure
    of sensitive information or denial of service.
    (CVE-2012-3450)"
  );
  # http://packetstormsecurity.org/files/113551/PHP-5.4.3-PDO-Access-Violation.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6adf7abc");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=61755");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.4.4");
  # http://0x1byte.blogspot.com/2011/04/php-phar-extension-heap-overflow.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99140286");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 5.4.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

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

if (report_paranoia < 2 && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

if (version !~ "^5\.4\.") exit(0, "The web server listening on port "+port+" does not use PHP version 5.4.x.");
if (version =~ "^5\.4\.[0-3]($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : '+source +
      '\n  Installed version : '+version+
      '\n  Fixed version     : 5.4.4\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
