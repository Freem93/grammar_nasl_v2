#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92554);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/10/10 14:39:21 $");

  script_cve_id(
    "CVE-2016-5385",
    "CVE-2016-5399",
    "CVE-2016-6207",
    "CVE-2016-6289",
    "CVE-2016-6290",
    "CVE-2016-6291",
    "CVE-2016-6292",
    "CVE-2016-6293",
    "CVE-2016-6294",
    "CVE-2016-6295",
    "CVE-2016-6296",
    "CVE-2016-6297"
  );
  script_bugtraq_id(
    91821,
    92051,
    92073,
    92074,
    92078,
    92094,
    92095,
    92097,
    92099
  );
  script_osvdb_id(
    141667,
    141674,
    141675,
    141942,
    141943,
    141944,
    141945,
    141946,
    141953,
    141954,
    141957,
    141958,
    142018,
    142104,
    142133
  );
  script_xref(name:"CERT", value:"797896");
  script_xref(name:"EDB-ID", value:"40155");

  script_name(english:"PHP 5.5.x < 5.5.38 Multiple Vulnerabilities (httpoxy)");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 5.5.x prior to 5.5.38. It is, therefore, affected by
multiple vulnerabilities :

  - A man-in-the-middle vulnerability exists, known as
    'httpoxy', due to a failure to properly resolve
    namespace conflicts in accordance with RFC 3875 section
    4.1.18. The HTTP_PROXY environment variable is set based
    on untrusted user data in the 'Proxy' header of HTTP
    requests. The HTTP_PROXY environment variable is used by
    some web client libraries to specify a remote proxy
    server. An unauthenticated, remote attacker can exploit
    this, via a crafted 'Proxy' header in an HTTP request,
    to redirect an application's internal HTTP traffic to an
    arbitrary proxy server where it may be observed or
    manipulated. (CVE-2016-5385)

  - An overflow condition exists in the php_bz2iop_read()
    function within file ext/bz2/bz2.c due to improper
    handling of error conditions. An unauthenticated, remote
    attacker can exploit this, via a crafted request, to
    execute arbitrary code. (CVE-2016-5399)

  - A flaw exists in the GD Graphics Library (libgd),
    specifically in the gdImageScaleTwoPass() function
    within file gd_interpolation.c, due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this to cause a denial of
    service condition. (CVE-2016-6207)

  - An integer overflow condition exists in the
    virtual_file_ex() function within file
    Zend/zend_virtual_cwd.c due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this to cause a denial of service condition
    or the execution of arbitrary code. (CVE-2016-6289)

  - A use-after-free error exists within the file
    ext/session/session.c when handling 'var_hash'
    destruction. An unauthenticated, remote attacker can
    exploit this to deference already freed memory,
    resulting in the execution of arbitrary code.
    (CVE-2016-6290)

  - An out-of-bounds read error exists in the
    exif_process_IFD_in_MAKERNOTE() function within file
    ext/exif/exif.c. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition or
    disclose memory contents. (CVE-2016-6291)

  - A NULL pointer dereference flaw exists in the
    exif_process_user_comment() function within file
    ext/exif/exif.c. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition.
    (CVE-2016-6292)

  - Multiple out-of-bounds read errors exist in the
    locale_accept_from_http() function within file
    ext/intl/locale/locale_methods.c. An unauthenticated,
    remote attacker can exploit these to cause a denial of
    service condition or disclose memory contents.
    (CVE-2016-6293, CVE-2016-6294)

  - A use-after-free error exists within file
    ext/snmp/snmp.c when handling garbage collection during
    deserialization of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    deference already freed memory, resulting in the
    execution of arbitrary code. (CVE-2016-6295)

  - A heap-based buffer overflow condition exists in the
    simplestring_addn() function within file simplestring.c
    due to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2016-6296)

  - An integer overflow condition exists in the
    php_stream_zip_opener() function within file
    ext/zip/zip_stream.c due to improper validation of
    user-supplied input when handling zip streams. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2016-6297)

  - An out-of-bounds read error exists in the GD Graphics
    Library (libgd), specifically in the
    gdImageScaleBilinearPalette() function within file
    gd_interpolation.c, when handling transparent color. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or disclose
    memory contents. (VulnDB 141674)

  - A heap-based buffer overflow condition exists in the
    mdecrypt_generic() function within file
    ext/mcrypt/mcrypt.c due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this to cause a denial of service condition
    or the execution of arbitrary code. (VulnDB 141953)

  - A NULL write flaw exists in the GD Graphics Library
    (libgd) in the gdImageColorTransparent() function due to
    improper handling of negative transparent colors. A
    remote attacker can exploit this to disclose memory
    contents. (VulnDB 142104)

  - An overflow condition exists in the php_url_prase_ex()
    function due to improper validation of user-supplied
    input. A remote attacker can exploit this to cause a
    buffer overflow, resulting in a denial of service
    condition. (VulnDB 142133)");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.5.38");
  script_set_attribute(attribute:"see_also", value:"https://httpoxy.org");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.5.38 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (version =~ "^5(\.5)?$")
  audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^5\.5\.") audit(AUDIT_NOT_DETECT, "PHP version 5.5.x", port);

if (version =~ "^5\.5\." && ver_compare(ver:version, fix:"5.5.38", strict:FALSE) < 0){
  security_report_v4(
  port  : port,
  extra :
    '\n  Version source    : ' + source +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 5.5.38' +
    '\n',
  severity:SECURITY_HOLE
  );
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
