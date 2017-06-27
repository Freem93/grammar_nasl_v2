#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93077);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_osvdb_id(
    143096,
    143100,
    143101,
    143102,
    143103,
    143104,
    143105,
    143106,
    143107,
    143108,
    143109,
    143110,
    143111,
    143112,
    143113,
    143114,
    143116,
    143117,
    143118
  );

  script_name(english:"PHP 5.6.x < 5.6.25 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 5.6.x prior to 5.6.25. It is, therefore, affected by
multiple vulnerabilities :

  - An unspecified flaw exists in the object_common2()
    function in var_unserializer.c that occurs when handling
    objects during deserializaiton. An unauthenticated,
    remote attacker can exploit this to execute arbitrary
    code. (VulnDB 143096)

  - An integer overflow condition exists in the
    php_snmp_parse_oid() function in snmp.c. An
    unauthenticated, remote attacker can exploit this to
    cause a heap-based buffer overflow, resulting in the
    execution of arbitrary code. (VulnDB 143100)

  - An integer truncation flaw exists in the select_colors()
    function in gd_topal.c that is triggered when handling
    the number of colors. An unauthenticated, remote
    attacker can exploit to cause a heap-based buffer
    overflow, resulting in the execution of arbitrary code.
    (VulnDB 143101)

  - An overflow condition exists in the sql_regcase()
    function in ereg.c due to improper handling of overly
    long strings. An unauthenticated, remote attacker
    can exploit this to corrupt memory, resulting in the
    execution of arbitrary code. (VulnDB 143102)

  - A NULL pointer dereference flaw exists in the
    php_wddx_pop_element() function in wddx.c that is
    triggered during the handling of Base64 binary values.
    An unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (VulnDB 143103)

  - An unspecified NULL pointer dereference flaw exists in
    the php_wddx_pop_element() function in wddx.c. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (VulnDB 143104)

  - An integer overflow condition exists in the
    php_base64_encode() function in base64.c that occurs
    when handling overly long strings. An unauthenticated, 
    remote attacker can exploit this to execute arbitrary
    code. (VulnDB 143105)

  - A NULL pointer dereference flaw exists in the
    php_wddx_deserialize_ex() function in wddx.c that occurs
    during the handling of invalid XML content. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (VulnDB 143106)

  - An integer overflow condition exists in the
    php_quot_print_encode() function in quot_print.c that
    occurs when handling overly long strings. An
    unauthenticated, remote attacker can exploit this to
    cause a heap-based buffer overflow condition, resulting
    in the execution of arbitrary code. (VulnDB 143107)

  - A use-after-free error exists in the unserialize()
    function in var.c. An unauthenticated, remote attacker
    can exploit this to dereference already freed memory,
    resulting in the execution of arbitrary code.
    (VulnDB 143108)

  - A flaw exists in the php_ftp_fopen_connect() function in 
    ftp_fopen_wrapper.c that allows a man-in-the-middle
    attacker to silently downgrade to regular FTP even if a
    secure method has been requested. (VulnDB 143109)

  - A flaw exists in the php_wddx_process_data() function in
    wddx.c that occurs when deserializing invalid dateTime
    values. An unauthenticated, remote attacker can exploit
    this to cause a denial of service condition.
    (VulnDB 143110)

  - A flaw exists in the exif_process_IFD_in_TIFF() function
    in exif.c that occurs when handling TIFF image content.
    An unauthenticated, remote attacker can exploit this to
    disclose memory contents. (VulnDB 143111)

  - An integer overflow condition exists in the
    php_url_encode() function in url.c that occurs when
    handling overly long strings. An unauthenticated, remote
    attacker can exploit this to corrupt memory, resulting
    in the execution of arbitrary code. (VulnDB 143112)

  - An integer overflow condition exists in the
    php_uuencode() function in uuencode.c. An
    unauthenticated, remote attacker can exploit this to
    corrupt memory, resulting in the execution of arbitrary
    code. (VulnDB 143113)

  - An integer overflow condition exists in the
    bzdecompress() function in bz2.c. An unauthenticated,
    remote attacker can exploit this to corrupt memory,
    resulting in the execution of arbitrary code.
    (VulnDB 143114)

  - An indexing flaw exists in the imagegammacorrect()
    function in gd.c that occurs when handling negative
    gamma values. An unauthenticated, remote attacker can
    exploit this to write a NULL to an arbitrary memory
    location, resulting in a denial of service condition or
    the execution of arbitrary code. (VulnDB 143116)

  - An integer overflow condition exists in the
    curl_escape() function in interface.c that occurs when
    handling overly long escaped strings. An 
    unauthenticated, remote attacker can exploit this to
    corrupt memory, resulting in the execution of arbitrary
    code. (VulnDB 143117)

  - An unspecified flaw exists in session.c that occurs
    when handling session names. An unauthenticated, remote
    attacker can exploit this to inject arbitrary data into
    sessions. (VulnDB 143118)");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.6.25");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.6.25 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/23");

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
if (version =~ "^5(\.6)?$")
  audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^5\.6\.") audit(AUDIT_NOT_DETECT, "PHP version 5.6.x", port);

if (version =~ "^5\.6\." && ver_compare(ver:version, fix:"5.6.25", strict:FALSE) < 0){
  security_report_v4(
  port  : port,
  extra :
    '\n  Version source    : ' + source +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 5.6.25' +
    '\n',
  severity:SECURITY_HOLE
  );
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
