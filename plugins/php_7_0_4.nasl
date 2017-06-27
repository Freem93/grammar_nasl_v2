#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90009);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/06/20 20:49:18 $");

  script_cve_id(
    "CVE-2016-3185",
    "CVE-2016-4344",
    "CVE-2016-4345",
    "CVE-2016-4346"
  );
  script_osvdb_id(
    135226,
    135227,
    135340,
    135341,
    135342,
    135343,
    135345,
    135346,
    135347,
    137757,
    137758
  );

  script_name(english:"PHP 7.0.x < 7.0.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 7.0.x prior to 7.0.4. It is, therefore, affected by multiple
vulnerabilities :

  - A type confusion error exists in file
    ext/soap/php_http.c in the make_http_soap_request()
    function when handling cookie data. An unauthenticated,
    remote attacker can exploit this to execute arbitrary
    code. (CVE-2016-3185)

  - Multiple integer overflow conditions exist in file
    ext/xml/xml.c in the xml_utf8_encode functions due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit these to
    cause a heap-based buffer overflow, resulting in a
    denial of service or the execution of arbitrary code.
    (CVE-2016-4344)

  - An integer overflow condition exists in the
    php_filter_encode_url() function due to improper
    validation of user-supplied input. A remote attacker can
    exploit this to cause a heap-based buffer overflow,
    resulting in a denial of service or th execution of
    arbitrary code. (CVE-2016-4345)

  - An overflow condition exists in the xml_utf8_encode
    functions due to improper validation of user-supplied
    input. A remote attacker can exploit this to cause a
    heap-based buffer overflow, resulting in a denial of
    service condition or the execution of arbitrary code.
    (CVE-2016-4346)

  - A flaw exists when handling the third call while running
    function.forward-static-call.php. An unauthenticated,
    remote attacker can exploit this to cause a denial of
    service by crashing the interpreter. (VulnDB 135340)

  - An integer overflow condition exists in file
    ext/standard/string.c in the php_implode() function due
    to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    cause a heap-based buffer overflow, resulting in a
    denial of service or the execution of arbitrary code.
    (VulnDB 135341)

  - An integer overflow condition exists in file
    ext/standard/string.c in the zend_string_alloc()
    function due to improper validation of user-supplied
    input. An unauthenticated, remote attacker can exploit
    this to execute arbitrary code. (VulnDB 135342)

  - A stack corruption issue exists when handling certain
    Magento2 commands that allows an unauthenticated,
    remote attacker to cause a denial of service.
    (VulnDB 135343)

  - A flaw exists in file sapi/cli/php_cli_server.c due to
    the built-in HTTP server not properly restricting file
    requests. An unauthenticated, remote attacker can
    exploit this to access arbitrary files. (VulnDB 135345)

  - A use-after-free error exists in Zend Opcache when
    updating cached directory names that have been cached in
    the current working directory. An unauthenticated,
    remote attacker can exploit this to deference already
    freed memory, resulting in the execution of arbitrary
    code. (VulnDB 135346)

  - A NULL pointer dereference flaw exists in file
    ext/zip/php_zip.c in the Zip::ExtractTo() method that
    allows an unauthenticated, remote attacker to cause
    a denial of service. (VulnDB 135347)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-7.php#7.0.4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/17");

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
if (version =~ "^7(\.0)?$")
  audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^7\.0\.") audit(AUDIT_NOT_DETECT, "PHP version 7.0.x", port);

if (version !~ "^7\.0\.[0-3]([^0-9]|$)")
  audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);

security_report_v4(
  port  : port,
  extra :
    '\n  Version source    : ' + source +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 7.0.4' +
    '\n',
  severity:SECURITY_HOLE
);
