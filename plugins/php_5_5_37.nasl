#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91897);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/10/10 14:39:21 $");

  script_cve_id(
    "CVE-2015-8874",
    "CVE-2016-5766",
    "CVE-2016-5767",
    "CVE-2016-5768",
    "CVE-2016-5769",
    "CVE-2016-5770",
    "CVE-2016-5771",
    "CVE-2016-5772",
    "CVE-2016-5773"
  );
  script_bugtraq_id(
    90714,
    91393,
    91395,
    91396,
    91397,
    91398,
    91399,
    91401,
    91403
  );
  script_osvdb_id(
    125857,
    140377,
    140378,
    140379,
    140380,
    140381,
    140382,
    140383,
    140384,
    140385,
    140386,
    140387,
    140388,
    140390,
    140391
  );

  script_name(english:"PHP 5.5.x < 5.5.37 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 5.5.x prior to 5.5.37. It is, therefore, affected by
multiple vulnerabilities :

  - A denial of service vulnerability exists in the GD
    graphics library in the gdImageFillToBorder() function
    within file gd.c when handling crafted images that have
    an overly large negative coordinate. An unauthenticated,
    remote attacker can exploit this, via a crafted image,
    to crash processes linked against the library.
    (CVE-2015-8874)

  - An integer overflow condition exists in the
    _gd2GetHeader() function in file ext/gd/libgd/gd_gd2.c
    due to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2016-5766)

  - An integer overflow condition exists in the
    gdImagePaletteToTrueColor() function within file
    ext/gd/libgd/gd.c due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this to cause a denial of service condition
    or the execution of arbitrary code. (CVE-2016-5767)

  - A double-free error exists in the
    _php_mb_regex_ereg_replace_exec() function within file
    ext/mbstring/php_mbregex.c when handling a failed
    callback execution. An unauthenticated, remote attacker
    can exploit this to execute arbitrary code.
    (CVE-2016-5768)

  - An integer overflow condition exists within file
    ext/mcrypt/mcrypt.c due to improper validation of
    user-supplied input when handling data values. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2016-5769)

  - An integer overflow condition exists within file
    ext/spl/spl_directory.c, triggered by an int/size_t
    type confusion error, that allows an unauthenticated,
    remote attacker to have an unspecified impact.
    (CVE-2016-5770)

  - A use-after-free error exists in the garbage collection
    algorithm within file ext/spl/spl_array.c. An
    unauthenticated, remote attacker can exploit this to
    dereference already freed memory, resulting in the
    execution of arbitrary code. (CVE-2016-5771)

  - A double-free error exists in the
    php_wddx_process_data() function within file
    ext/wddx/wddx.c when handling specially crafted XML
    content. An unauthenticated, remote attacker
    can exploit this to execute arbitrary code.
    (CVE-2016-5772)

  - A use-after-free error exists in the garbage collection
    algorithm within file ext/zip/php_zip.c. An
    unauthenticated, remote attacker can exploit this to
    dereference already freed memory, resulting in the
    execution of arbitrary code. (CVE-2016-5773)

  - An integer overflow condition exists in the
    json_decode() and json_utf8_to_utf16() functions within
    file ext/standard/php_smart_str.h due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this to cause a denial of
    service condition or the execution of arbitrary code.
    (VulnDB 140378)

  - An out-of-bounds read error exists in the
    pass2_no_dither() function within file
    ext/gd/libgd/gd_topal.c that allows an unauthenticated,
    remote attacker to cause a denial of service condition
    or disclose memory contents. (VulnDB 140379)

  - An integer overflow condition exists within file
    ext/standard/string.c when handling string lengths due
    to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    have an unspecified impact. (VulnDB 140380)

  - A NULL pointer dereference flaw exists in the
    _gdScaleVert() function within file
    ext/gd/libgd/gd_interpolation.c that is triggered when
    handling _gdContributionsCalc return values. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (VulnDB 140382)

  - An integer overflow condition exists in the nl2br()
    function within file ext/standard/string.c when handling
    new_length values due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this to have an unspecified impact.
    (VulnDB 140385)

  - An integer overflow condition exists in multiple
    functions within file ext/standard/string.c when
    handling string values due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this to have an unspecified impact.
    (VulnDB 140386)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.5.37");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.5.37 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/01");

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
if (version =~ "^5(\.5)?$")
  audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^5\.5\.") audit(AUDIT_NOT_DETECT, "PHP version 5.5.x", port);

if (version =~ "^5\.5\." && ver_compare(ver:version, fix:"5.5.37", strict:FALSE) < 0){
  security_report_v4(
  port  : port,
  extra :
    '\n  Version source    : ' + source +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 5.5.37' +
    '\n',
  severity:SECURITY_HOLE
  );
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);

