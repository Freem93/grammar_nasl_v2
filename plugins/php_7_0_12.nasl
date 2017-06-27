#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94107);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_osvdb_id(
    145598,
    145600,
    145601,
    145603,
    145604,
    145605,
    145606,
    145609,
    145610,
    145611,
    145613,
    145614
  );

  script_name(english:"PHP 7.0.x < 7.0.12 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 7.0.x prior to 7.0.12. It is, therefore, affected by
multiple vulnerabilities :

  - A NULL pointer dereference flaw exists in the
    SimpleXMLElement::asXML() function within file
    ext/simplexml/simplexml.c. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition. (VulnDB 145598)

  - A flaw exists in the openssl_random_pseudo_bytes()
    function within file ext/openssl/openssl.c when handling
    strings larger than 2GB. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition. (VulnDB 145600)

  - A flaw exists in the openssl_encrypt() function within
    file ext/openssl/openssl.c when handling strings larger
    than 2GB. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition.
    (VulnDB 145601)

  - A flaw exists in the _bc_new_num_ex() function within
    file ext/bcmath/libbcmath/src/init.c when handling
    values passed via the 'scale' parameter. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (VulnDB 145603)

  - A flaw exists in the php_resolve_path() function within
    file main/fopen_wrappers.c when handling negative size
    values passed via the 'filename' parameter. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (VulnDB 145604)

  - A flaw exists in the dom_document_save_html() function
    within file ext/dom/document.c due to missing NULL
    checks. An unauthenticated, remote attacker can exploit
    this to cause a denial of service condition.
    (VulnDB 145605)

  - A use-after-free error exists in the unserialize()
    function that allows an unauthenticated, remote attacker
    to dereference already freed memory, resulting in the
    execution of arbitrary code. (VulnDB 145606)

  - An integer overflow condition exists in the
    number_format() function within file ext/standard/math.c
    when handling 'decimals' and 'dec_point' parameters that
    have values that are equal or close to 0x7fffffff. An
    unauthenticated, remote attacker can exploit this to
    cause a heap buffer overflow, resulting in a denial of
    service condition or the execution of arbitrary code.
    (VulnDB 145609)

  - A stack-based overflow condition exists in the
    ResourceBundle::create and ResourceBundle::getLocales
    methods and their respective functions within file
    ext/intl/resourcebundle/resourcebundle_class.c due to
    improper validation of input passed via the 'bundlename'
    parameter. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition or
    the execution or arbitrary code. (VulnDB 145610)

  - An integer overflow condition exists in the
    php_pcre_replace_impl() function within file
    ext/pcre/php_pcre.c due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this to cause a heap-based buffer overflow,
    resulting in a denial of service condition or the
    execution of arbitrary code. (VulnDB 145611)

  - A flaw exists in file ext/date/php_date.c within
    the php_date_interval_initialize_from_hash() function,
    when deserializing DateInterval objects, that allows
    an unauthenticated, remote attacker to cause an
    unspecified impact. (VulnDB 145613)

  - An unspecified flaw exists in the
    SplObjectStorage::unserialize() function within file
    ext/spl/spl_observer.c due to allowing the use of
    non-objects as keys. An unauthenticated, remote attacker
    can exploit this to cause an unspecified impact.
    (VulnDB 145614)");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-7.php#7.0.12");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.0.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/18");

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

fix = "7.0.12";
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
