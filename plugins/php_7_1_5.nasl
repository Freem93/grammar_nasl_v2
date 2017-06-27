#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100421);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/25 17:11:26 $");

  script_cve_id(
    "CVE-2017-8923",
    "CVE-2017-9119"
  );
  script_bugtraq_id(
    98518,
    98596
  );
  script_osvdb_id(
    157495,
    157879
  );
  script_xref(name:"IAVB", value:"2017-B-0060");

  script_name(english:"PHP 7.1.x < 7.1.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 7.1.x prior to 7.1.5. It is, therefore, affected by the
following vulnerabilities :

  - A memory allocation issue exists in the
    zend_string_extend() function in file Zend/zend_string.h
    when concatenating strings due to a failure to prevent
    changes to string objects that result in a negative
    length. An unauthenticated, remote attacker can exploit
    this to cause a denial of service condition or possibly
    other unspecified impact. (CVE-2017-8923)

  - A memory allocation issue exists in the
    i_zval_ptr_dtor() function in Zend/zend_variables.h when
    allocating large amounts of memory. An unauthenticated,
    remote attacker can exploit this, via crafted operations
    on array data structures, to cause a denial of service
    condition. (CVE-2017-9119)");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-7.php#7.1.5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.1.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (version =~ "^7(\.1)?$") audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^7\.1\.") audit(AUDIT_NOT_DETECT, "PHP version 7.1.x", port);

fix = "7.1.5";
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
