#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90361);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/06/20 20:49:18 $");

  script_osvdb_id(
    122863,
    136483,
    136484,
    136485,
    136486
  );
  script_xref(name:"EDB-ID", value:"39645");
  script_xref(name:"EDB-ID", value:"39653");

  script_name(english:"PHP 5.6.x < 5.6.20 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP on the remote web server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 5.6.x prior to 5.6.20. It is, therefore, affected by
multiple vulnerabilities :

  - A buffer over-write condition exists in the finfo_open()
    function due to improper validation of magic files. An
    unauthenticated, remote attacker can exploit this, via a
    crafted file, to cause a denial of service or to execute
    arbitrary code. (VulnDB 122863)

  - A flaw exists in the php_snmp_error() function within
    file ext/snmp/snmp.c that is triggered when handling
    format string specifiers. An unauthenticated, remote
    attacker can exploit this, via a crafted SNMP object,
    to cause a denial of service or to execute arbitrary
    code. (VulnDB 136483)

  - An invalid memory write error exists when handling
    the path of phar file names that allows an attacker
    to have an unspecified impact. (VulnDB 136484)

  - A flaw exists in the mbfl_strcut() function within file
    ext/mbstring/libmbfl/mbfl/mbfilter.c when handling
    negative parameter values. An unauthenticated, remote
    attacker can exploit this to cause a denial of service.
    (VulnDB 136485)

  - An integer overflow condition exists in the
    php_raw_url_encode() function within file
    ext/standard/url.c due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this to have an unspecified impact.
    (VulnDB 136486)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.6.20");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.6.20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/06");

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

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

# Check that it is the correct version of PHP
if (version =~ "^5(\.6)?$") audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^5\.6\.") audit(AUDIT_NOT_DETECT, "PHP version 5.6.x", port);

if (version !~ "^5\.6\.([0-9]|1[0-9])($|[^0-9])")
  audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);

security_report_v4(
  port  : port,
  extra :
    '\n  Version source    : '+source +
    '\n  Installed version : '+version +
    '\n  Fixed version     : 5.6.20' +
    '\n',
  severity:SECURITY_HOLE
);
