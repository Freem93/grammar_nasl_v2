#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94956);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/19 15:55:08 $");

  script_osvdb_id(
    145227,
    146957,
    147321
  );

  script_name(english:"PHP 7.0.x < 7.0.13 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 7.0.x prior to 7.0.13. It is, therefore, affected by
multiple vulnerabilities :

  - A flaw exists in the parse_url() function due to
    returning the incorrect host. An unauthenticated, remote
    attacker can exploit this to have a multiple impacts
    depending on how the function is implemented, which can
    include bypassing authentication or conducting open
    redirection and server-side request forgery attacks.
    (VulnDB 145227)

  - An integer overflow condition exists in the
    _php_imap_mail() function in file ext/imap/php_imap.c
    when handling overly long strings. An unauthenticated,
    remote attacker can exploit this to cause a
    heap-based buffer overflow, resulting in a denial of
    service condition or the execution of arbitrary code.
    (VulnDB 146957)

  - An integer overflow condition exists in the
    gdImageAALine() function within file ext/gd/libgd/gd.c
    due to improper validation of line limit values. An
    unauthenticated, remote attacker can exploit this to
    cause an out-of-bounds memory read or write, resulting
    in a denial of service condition, the disclosure of
    memory contents, or the execution of arbitrary code.
    (VulnDB 147321)

Note that this software is reportedly affected by other
vulnerabilities as well that have not been fixed yet in version
7.0.13.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-7.php#7.0.13");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.0.13 or later.

Note that this software is reportedly affected by other
vulnerabilities as well. Patches for these have been committed to the
source code repository, but until they are incorporated into the next
release of the software, manually installing an updated snapshot is
the only known solution.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

if (report_paranoia < 2 && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

# Check that it is the correct version of PHP
if (version =~ "^7(\.0)?$") audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^7\.0\.") audit(AUDIT_NOT_DETECT, "PHP version 7.0.x", port);

fix = "7.0.13";
if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Version source    : ' + source +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
