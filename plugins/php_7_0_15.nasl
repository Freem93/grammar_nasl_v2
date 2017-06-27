#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96800);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/27 16:20:34 $");

  script_cve_id(
    "CVE-2015-2787",
    "CVE-2016-7479",
    "CVE-2017-5340",
    "CVE-2016-10158",
    "CVE-2016-10159",
    "CVE-2016-10160",
    "CVE-2016-10161",
    "CVE-2016-10162"
  );
  script_bugtraq_id(
    73431,
    95151,
    95371,
    95668,
    95764,
    95768,
    95774,
    95783
  );
  script_osvdb_id(
    119774,
    149442,
    149621,
    149623,
    149628,
    149629,
    149664,
    149665,
    149666,
    150227,
    150228,
    150576,
    150680
  );

  script_name(english:"PHP 7.0.x < 7.0.15 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 7.0.x prior to 7.0.15. It is, therefore, affected by the
following vulnerabilities :

  - A remote code execution vulnerability exists due to a
    use-after-free error in the unserialize() function that
    is triggered when using DateInterval input. An
    unauthenticated, remote attacker can exploit this to
    dereference already freed memory, resulting in a denial
    of service condition or the execution of arbitrary code.
    (CVE-2015-2787)

  - A use-after-free error exists that is triggered when
    handling unserialized object properties. An 
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary code.
    (CVE-2016-7479)

  - An integer overflow condition exists in the
    _zend_hash_init() function in zend_hash.c due to
    improper validation of unserialized objects. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2017-5340)

  - A floating pointer exception flaw exists in the
    exif_convert_any_to_int() function in exif.c that is
    triggered when handling TIFF and JPEG image tags. An
    unauthenticated, remote attacker can exploit this to
    cause a crash, resulting in a denial of service
    condition. (CVE-2016-10158)

  - An integer overflow condition exists in the
    phar_parse_pharfile() function in phar.c due to improper
    validation when handling phar archives. An
    unauthenticated, remote attacker can exploit this to
    cause a crash, resulting in a denial of service
    condition. (CVE-2016-10159)

  - An off-by-one overflow condition exists in the
    phar_parse_pharfile() function in phar.c due to improper
    parsing of phar archives. An unauthenticated, remote
    attacker can exploit this to cause a crash, resulting in
    a denial of service condition. (CVE-2016-10160)

  - An out-of-bounds read error exists in the
    finish_nested_data() function in var_unserializer.c due
    to improper validation of unserialized data. An
    unauthenticated, remote attacker can exploit this to
    cause a crash, resulting in a denial of service
    condition or the disclosure of memory contents.
    (CVE-2016-10161)

  - A NULL pointer dereference flaw exists in the
    php_wddx_pop_element() function in wddx.c due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    cause a crash, resulting in a denial of service
    condition. (CVE-2016-10162)

  - An signed integer overflow condition exists in gd_io.c
    due to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    have an unspecified impact. (VulnDB 150680)

  - A type confusion flaw exists that is triggered during
    the deserialization of specially crafted GMP objects. An
    unauthenticated, remote attacker can exploit this to
    cause a crash, resulting in a denial of service
    condition. (VulnDB 150227)

  - A type confusion error exists that is triggered when
    deserializing ZVAL objects. An unauthenticated, remote
    attacker can exploit this to execute arbitrary code.
    (VulnDB 150228)

  - An out-of-bounds read error exists in the
    phar_parse_pharfile() function in phar.c due to improper
    parsing of phar archives. An unauthenticated, remote
    attacker can exploit this to cause a crash, resulting in
    a denial of service condition. (VulnDB 149621)

  - A denial of service vulnerability exists in the bundled
    GD Graphics Library (LibGD) in the
    gdImageCreateFromGd2Ctx() function in gd_gd2.c due to
    improper validation of images. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted image, to crash the process. (VulnDB 150576)");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-7.php#7.0.15");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.0.15 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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

fix = "7.0.15";
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
