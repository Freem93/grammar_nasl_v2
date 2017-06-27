#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76281);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/06/20 20:49:18 $");

  script_cve_id(
    "CVE-2014-0207",
    "CVE-2014-3478",
    "CVE-2014-3479",
    "CVE-2014-3480",
    "CVE-2014-3487",
    "CVE-2014-3515",
    "CVE-2014-3981",
    "CVE-2014-4049",
    "CVE-2014-4721"
  );
  script_bugtraq_id(
    67837,
    68007,
    68120,
    68237,
    68238,
    68239,
    68241,
    68243,
    68423,
    68550
  );
  script_osvdb_id(
    107725,
    107994,
    108462,
    108463,
    108464,
    108465,
    108466,
    108467,
    108468,
    130082,
    130083
  );

  script_name(english:"PHP 5.4.x < 5.4.30 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a version of PHP that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP 5.4.x installed on the
remote host is a version prior to 5.4.30. It is, therefore, affected
by the following vulnerabilities :

  - Boundary checking errors exist related to the
    Fileinfo extension, Composite Document Format (CDF)
    handling and the functions 'cdf_read_short_sector',
    'cdf_check_stream_offset', 'cdf_count_chain', and
    'cdf_read_property_info'. (CVE-2014-0207, CVE-2014-3479,
    CVE-2014-3480, CVE-2014-3487)

  - A pascal string size handling error exists related to
    the Fileinfo extension and the function 'mconvert'.
    (CVE-2014-3478)

  - A type-confusion error exists related to the Standard
    PHP Library (SPL) extension and the function
    'unserialize'. (CVE-2014-3515)

  - An error exists related to configuration scripts and
    temporary file handling that could allow insecure file
    usage. (CVE-2014-3981)

  - A heap-based buffer overflow error exists related to the
    function 'dns_get_record' that could allow execution of
    arbitrary code. (CVE-2014-4049)

  - A type-confusion error exists related to the function
    'php_print_info' that could allow disclosure of
    sensitive information. (CVE-2014-4721)

  - An out-of-bounds read error exists in the
    timelib_meridian_with_check() function due to a failure
    to properly check string ends. A remote attacker can
    exploit this to cause a denial of service condition or
    to disclose memory contents. (VulnDB 130082)

  - An out-of-bounds read error exists in the
    date_parse_from_format() function due to a failure
    in the date parsing routines to properly check string
    ends. A remote attacker can exploit this to cause a
    denial of service condition or to disclose memory
    contents. (VulnDB 130083)

  - An error exists related to unserialization and
    'SplFileObject' handling that could allow denial of
    service attacks. (Bug #67072)

  - A double free error exists related to the Intl
    extension and the method 'Locale::parseLocale' having
    unspecified impact. (Bug #67349)

  - A buffer overflow error exists related to the Intl
    extension and the functions 'locale_get_display_name'
    and 'uloc_getDisplayName' having unspecified impact.
    (Bug #67397)

Note that Nessus has not attempted to exploit these issues, but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.4.30");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=67072");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=67326");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=67349");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=67390");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=67397");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=67410");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=67411");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=67412");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=67413");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=67432");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=67492");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=67498");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=67253");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=67251");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/29");
  script_set_attribute(attribute:"see_also", value:"https://www.sektioneins.de/en/blog/14-07-04-phpinfo-infoleak.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 5.4.30 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);
php = get_php_from_kb(port:port, exit_on_fail:TRUE);

version = php["ver"];
source = php["src"];

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

# Check that it is the correct version of PHP
if (version =~ "^5(\.4)?$") audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^5\.4\.") audit(AUDIT_NOT_DETECT, "PHP version 5.4.x", port);

if (version =~ "^5\.4\.([0-9]|[0-2][0-9])($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : '+source +
      '\n  Installed version : '+version+
      '\n  Fixed version     : 5.4.30\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
