#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90922);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/06/20 20:49:18 $");

  script_cve_id(
    "CVE-2016-3074",
    "CVE-2016-3078"
  );
  script_osvdb_id(
    137447,
    137738,
    137781,
    137782,
    137783,
    137784
  );
  script_xref(name:"EDB-ID", value:"39736");
  script_xref(name:"EDB-ID", value:"39742");

  script_name(english:"PHP 7.0.x < 7.0.6 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 7.0.x prior to 7.0.6. It is, therefore, affected by multiple
vulnerabilities :

  - A signedness error exists in the GD Graphics library
    within file gd_gd2.c due to improper validation of
    user-supplied input when handling compressed GD2 data.
    An unauthenticated, remote attacker can exploit this to
    cause a heap-based buffer overflow, resulting in a
    denial of service condition or the execution of
    arbitrary code. (CVE-2016-3074)

  - An integer overflow condition exists in ZipArchive in
    the getFromIndex() and getFromName() functions due to
    improper validation of user-supplied input when handling
    specially crafted ZIP files. An unauthenticated, remote
    attacker can exploit this to cause a heap-based buffer
    overflow, resulting in a denial of service condition or
    the execution of arbitrary code. (CVE-2016-3078)

  - An out-of-bounds read error exists within file
    ext/intl/grapheme/grapheme_string.c when handling
    negative offsets in the zif_grapheme_stripos() function.
    An unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or disclose memory
    contents. (VulnDB 137781)

  - An out-of-bounds read error exists in the php_str2num()
    function within file ext/bcmath/bcmath.c when handling
    negative scales. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition or
    the disclosure of memory contents. (VulnDB 137782)

  - An out-of-bounds read error exists in the
    exif_read_data() function within file ext/exif/exif.c
    when handling exif headers. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition or the disclosure of memory contents.
    (VulnDB 137783)

  - A flaw exists in the xml_parse_into_struct() function
    within file ext/xml/xml.c when handling specially
    crafted XML contents. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition. (VulnDB 137784)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-7.php#7.0.6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/05");

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

if (version =~ "^7\.0\." && ver_compare(ver:version, fix:"7.0.6", strict:FALSE) < 0){
  security_report_v4(
  port  : port,
  extra :
    '\n  Version source    : ' + source +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 7.0.6' +
    '\n',
  severity:SECURITY_HOLE
  );
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
