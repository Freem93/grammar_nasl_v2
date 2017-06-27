#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93657);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_cve_id(
    "CVE-2016-7412",
    "CVE-2016-7413",
    "CVE-2016-7414",
    "CVE-2016-7416",
    "CVE-2016-7417",
    "CVE-2016-7418"
  );
  script_bugtraq_id(
    93004,
    93005,
    93006,
    93007,
    93008,
    93011
  );
  script_osvdb_id(
    144259,
    144260,
    144261,
    144262,
    144263,
    144264,
    144269
  );

  script_name(english:"PHP 7.0.x < 7.0.11 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 7.0.x prior to 7.0.11. It is, therefore, affected by
multiple vulnerabilities :

  - An heap buffer overflow condition exists in the
    php_mysqlnd_rowp_read_text_protocol_aux() function
    within file ext/mysqlnd/mysqlnd_wireprotocol.c due to
    a failure to verify that a BIT field has the
    UNSIGNED_FLAG flag. An unauthenticated, remote attacker
    can exploit this, via specially crafted field metadata,
    to cause a denial of service condition. (CVE-2016-7412)

  - A use-after-free error exists in the
    wddx_stack_destroy() function within file
    ext/wddx/wddx.c when deserializing recordset elements.
    An unauthenticated, remote attacker can exploit this,
    via a specially crafted wddxPacket XML document, to
    cause a denial of service condition. (CVE-2016-7413)

  - An out-of-bounds access error exists in the
    phar_parse_zipfile() function within file ext/phar/zip.c
    due to a failure to ensure that the
    uncompressed_filesize field is large enough. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted archive, to cause a denial of service
    condition. (CVE-2016-7414)

  - A stack-based buffer overflow condition exists in the
    ICU4C library, specifically within file common/locid.cpp
    in the the msgfmt_format_message() function, due to a
    failure to properly restrict the locale length provided
    to the Locale class. An unauthenticated, remote attacker
    can exploit this, via a long first argument to a
    MessageFormatter::formatMessage() function call, to
    cause a denial of service condition. (CVE-2016-7416)

  - A flaw exists in the spl_array_get_dimension_ptr_ptr()
    function within file ext/spl/spl_array.c due to a
    failure to properly validate the return value and data
    type when deserializing SplArray. An unauthenticated,
    remote attacker can exploit this, via specially crafted
    serialized data, to cause a denial of service condition.
    (CVE-2016-7417)

  - An out-of-bounds read error exists in the
    php_wddx_push_element() function within file
    ext/wddx/wddx.c when handling an incorrect boolean
    element, which leads to mishandling the
    wddx_deserialize() call. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    wddxPacket XML document, to cause a denial of service
    condition. (CVE-2016-7418)

  - An out-of-bounds access error exists in the
    phar_parse_tarfile() function within file ext/phar/tar.c
    when handling the verification of signatures. An
    unauthenticated, remote attacker can exploit this to
    cause an unspecified impact. (VulnDB 144264)");
  script_set_attribute(attribute:"see_also", value:"https://secure.php.net/ChangeLog-7.php#7.0.11");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.0.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/22");

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

if (version =~ "^7\.0\." && ver_compare(ver:version, fix:"7.0.11", strict:FALSE) < 0){
  security_report_v4(
  port  : port,
  extra :
    '\n  Version source    : ' + source +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 7.0.11' +
    '\n',
  severity:SECURITY_HOLE
  );
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
