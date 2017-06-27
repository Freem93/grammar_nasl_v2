#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83033);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_cve_id(
    "CVE-2014-9709",
    "CVE-2015-1352",
    "CVE-2015-2301",
    "CVE-2015-2783",
    "CVE-2015-3307",
    "CVE-2015-3329",
    "CVE-2015-3330",
    "CVE-2015-3411",
    "CVE-2015-3412",
    "CVE-2015-4599",
    "CVE-2015-4600",
    "CVE-2015-4601",
    "CVE-2015-4602",
    "CVE-2015-4603",
    "CVE-2015-4604",
    "CVE-2015-4605"
  );
  script_bugtraq_id(
    71932,
    73037,
    73306,
    74204,
    74239,
    74240,
    74413,
    74703,
    75233,
    75241,
    75246,
    75249,
    75250,
    75251,
    75252,
    75255
  );
  script_osvdb_id(
    117469,
    117588,
    119650,
    120923,
    120925,
    120926,
    120927,
    120928,
    120930,
    120932,
    120938,
    121321,
    121398,
    122257,
    123639,
    123640,
    123677
  );

  script_name(english:"PHP 5.4.x < 5.4.40 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP 5.4.x running on the
remote web server is prior to 5.4.40. It is, therefore, affected by
multiple vulnerabilities :

  - An out-of-bounds read error exists in the GetCode_()
    function within file gd_gif_in.c that allows an
    unauthenticated, remote attacker to cause a denial of
    service condition or the disclosure of memory contents.
    (CVE-2014-9709)

  - A NULL pointer dereference flaw exists in the
    build_tablename() function within file pgsql.c in the
    PostgreSQL extension due to a failure to validate token
    extraction for table names. An authenticated, remote
    attacker can exploit this, via a crafted name, to cause
    a denial of service condition. (CVE-2015-1352)

  - A use-after-free error exists in the
    phar_rename_archive() function within file
    phar_object.c. An unauthenticated, remote attacker can
    exploit this, by attempting to rename a phar archive to
    an already existing file name, to cause a denial of
    service condition. (CVE-2015-2301)

  - An out-of-bounds read error exists in the Phar component
    due to improper validation of user-supplied input when
    handling phar parsing during unserialize() function
    calls. An unauthenticated, remote attacker can exploit
    this to cause a denial of service condition or the
    disclosure of memory contents. (CVE-2015-2783)

  - A memory corruption issue exists in the
    phar_parse_metadata() function in file ext/phar/phar.c
    due to improper validation of user-supplied input when
    parsing a specially crafted TAR archive. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2015-3307)

  - Multiple stack-based buffer overflow conditions exist in
    the phar_set_inode() function in file phar_internal.h
    when handling archive files, such as tar, zip, or phar
    files. An unauthenticated, remote attacker can exploit
    these to cause a denial of service condition or the
    execution or arbitrary code. (CVE-2015-3329)

  - A flaw exists in the Apache2handler SAPI component when
    handling pipelined HTTP requests that allows an
    unauthenticated, remote attacker to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2015-3330)

  - A flaw exists in multiple functions due to a failure to
    check for NULL byte (%00) sequences in a path when
    processing or reading a file. An unauthenticated, remote
    attacker can exploit this, via specially crafted input
    to an application calling those functions, to bypass
    intended restrictions and disclose potentially
    sensitive information. (CVE-2015-3411, CVE-2015-3412)

  - A type confusion error exists in multiple functions
    within file ext/soap/soap.c that is triggered when
    calling unserialize(). An unauthenticated, remote
    attacker can exploit this to disclose memory contents,
    cause a denial of service condition, or execute
    arbitrary code. (CVE-2015-4599, CVE-2015-4600)

  - Multiple type confusion errors exist within files
    ext/soap/php_encoding.c, ext/soap/php_http.c, and
    ext/soap/soap.c that allow an unauthenticated, remote
    attacker to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2015-4601)

  - A type confusion error exists in the
    __PHP_Incomplete_Class() function within file
    ext/standard/incomplete_class.c that allows an
    unauthenticated, remote attacker to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2015-4602)

  - A type confusion error exists in the
    exception::getTraceAsString() function within file
    Zend/zend_exceptions.c that allows a remote attacker to
    execute arbitrary code. (CVE-2015-4603)

  - A denial of service vulnerability exists due to a flaw
    in the bundled libmagic library, specifically in the
    mget() function within file softmagic.c. The function
    fails to maintain a certain pointer relationship. An
    unauthenticated, remote attacker can exploit this, via a
    crafted string, to crash the application.
    (CVE-2015-4604)

  - A denial of service vulnerability exists due to a flaw
    in the bundled libmagic library, specifically in the
    mcopy() function within file softmagic.c. The function
    fails to properly handle an offset that exceeds
    'bytecnt'. An unauthenticated, remote attacker can
    exploit this, via a crafted string, to crash the
    application. (CVE-2015-4605)

  - A use-after-free error exists in the sqlite3_close()
    function within file /ext/sqlite3/sqlite3.c when closing
    database connections. An unauthenticated, remote
    attacker can exploit this to execute arbitrary code.
    (VulnDB 120923)

  - A type confusion error exists in the
    php_stream_url_wrap_http_ex() function within file
    ext/standard/http_fopen_wrapper.c that allows an
    unauthenticated, remote attacker to execute arbitrary
    code. (VulnDB 120927)

  - A use-after-free error exists in the php_curl() function
    within file ext/curl/interface.c that allows an
    unauthenticated, remote attacker to execute arbitrary
    code. (VulnDB 120928)

  - A NULL pointer dereference flaw exists within file
    /ext/ereg/regex/regcomp.c that allows an
    unauthenticated, remote attacker attacker to cause a
    denial of service condition. (VulnDB 120932)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.4.40");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 5.4.40 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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
if (version =~ "^5(\.4)?$") audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^5\.4\.") audit(AUDIT_NOT_DETECT, "PHP version 5.4.x", port);

if (version =~ "^5\.4\.([0-9]|[1-3][0-9])($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : '+source +
      '\n  Installed version : '+version +
      '\n  Fixed version     : 5.4.40' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
