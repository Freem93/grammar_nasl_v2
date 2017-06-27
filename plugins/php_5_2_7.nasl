#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35043);
  script_version("$Revision: 1.28 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_cve_id(
    "CVE-2008-2371",
    "CVE-2008-2665",
    "CVE-2008-2666",
    "CVE-2008-2829",
    "CVE-2008-3658",
    "CVE-2008-3659",
    "CVE-2008-3660",
    "CVE-2008-5557",
    "CVE-2008-5624",
    "CVE-2008-5625",
    "CVE-2008-5658",
    "CVE-2008-7068",
    "CVE-2014-8626"
  );
  script_bugtraq_id(
    29796,
    29797,
    29829,
    30087,
    30649,
    31612,
    32383,
    32625,
    32688,
    32948,
    # 33498         nb: retired 29-Jan-2009
    70928
  );
  script_osvdb_id(
    46584,
    46638,
    46639,
    46641,
    46690,
    47796,
    47797,
    47798,
    50480,
    51477,
    52205,
    52206,
    52207,
    114250
  );

  script_name(english:"PHP 5 < 5.2.7 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP installed on the remote
host is prior to 5.2.7. It is, therefore, affected by multiple
vulnerabilities :

  - There is a buffer overflow flaw in the bundled PCRE
    library that allows a denial of service attack.
    (CVE-2008-2371)

  - Multiple directory traversal vulnerabilities exist in
    functions such as 'posix_access', 'chdir', and 'ftok'
    that allow a remote attacker to bypass 'safe_mode'
    restrictions. (CVE-2008-2665 and CVE-2008-2666).

  - A buffer overflow flaw in 'php_imap.c' may be triggered
    when processing long message headers due to the use of
    obsolete API calls. This can be exploited to cause a
    denial of service or to execute arbitrary code.
    (CVE-2008-2829)

  - A buffer overflow in the 'imageloadfont' function in
    'ext/gd/gd.c' can be triggered when a specially crafted
    font is given. This can be exploited to cause a denial
    of service or to execute arbitrary code. (CVE-2008-3658)

  - A buffer overflow flaw exists in PHP's internal function
    'memnstr' which can be exploited by an attacker using
    the delimiter argument to the 'explode' function. This
    can be used to cause a denial of service or to execute
    arbitrary code. (CVE-2008-3659)

  - When PHP is used as a FastCGI module, an attacker by
    requesting a file whose file name extension is preceded
    by multiple dots can cause a denial of service.
    (CVE-2008-3660)

  - A heap-based buffer overflow flaw in the mbstring
    extension can be triggered via a specially crafted
    string containing an HTML entity that is not handled
    during Unicode conversion. This can be exploited to
    execute arbitrary code.(CVE-2008-5557)

  - Improper initialization of global variables 'page_uid'
    and 'page_gid' when PHP is used as an Apache module
    allows the bypassing of security restriction due to
    SAPI 'php_getuid' function overloading. (CVE-2008-5624)

  - PHP does not enforce the correct restrictions when
    'safe_mode' is enabled through a 'php_admin_flag'
    setting in 'httpd.conf'. This allows an attacker, by
    placing a specially crafted 'php_value' entry in
    '.htaccess', to able to write to arbitrary files.
    (CVE-2008-5625)

  - The 'ZipArchive::extractTo' function in the ZipArchive
    extension fails to filter directory traversal sequences
    from file names. An attacker can exploit this to write
    to arbitrary files. (CVE-2008-5658)

  - Under limited circumstances, an attacker can cause a
    file truncation to occur when calling the 'dba_replace'
    function with an invalid argument. (CVE-2008-7068)

  - A buffer overflow error exists in the function
    'date_from_ISO8601' function within file 'xmlrpc.c'
    because user-supplied input is improperly validated.
    This can be exploited by a remote attacker to cause a
    denial of service or to execute arbitrary code.
    (CVE-2014-8626)");
  script_set_attribute(attribute:"see_also", value:"http://cxsecurity.com/issue/WLB-2008110041");
  script_set_attribute(attribute:"see_also", value:"http://cxsecurity.com/issue/WLB-2008110058");
  script_set_attribute(attribute:"see_also", value:"http://cxsecurity.com/issue/WLB-2008120011");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/Jun/237");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/Jun/238");
  script_set_attribute(attribute:"see_also", value:"http://www.openwall.com/lists/oss-security/2008/08/08/2");
  script_set_attribute(attribute:"see_also", value:"http://www.openwall.com/lists/oss-security/2008/08/13/8");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/Nov/674");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/Dec/90");
  script_set_attribute(attribute:"see_also", value:"http://bugs.php.net/bug.php?id=42862");
  script_set_attribute(attribute:"see_also", value:"http://bugs.php.net/bug.php?id=45151");
  script_set_attribute(attribute:"see_also", value:"http://bugs.php.net/bug.php?id=45722");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/5_2_7.php");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.2.7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.2.8 or later.

Note that version 5.2.7 has been removed from distribution because of
a regression in that version that results in the 'magic_quotes_gpc'
setting remaining off even if it was set to on.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 22, 119, 264);

  # CVE-2008-2665

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
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

if (version =~ "^5\.[01]\." ||
    version =~ "^5\.2\.[0-6]($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.2.7\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
