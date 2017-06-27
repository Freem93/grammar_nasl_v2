#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77285);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/03/30 18:51:39 $");

  script_cve_id(
    "CVE-2013-6712",
    "CVE-2014-0207",
    "CVE-2014-0237",
    "CVE-2014-0238",
    "CVE-2014-3515",
    "CVE-2014-3981",
    "CVE-2014-4049"
  );
  script_bugtraq_id(
    64018,
    67759,
    67765,
    67837,
    68007,
    68237,
    68243,
    69271,
    73385
  );
  script_osvdb_id(
    100440,
    107559,
    107560,
    107725,
    107994,
    108462,
    108463
  );

  script_name(english:"PHP 5.3.x < 5.3.29 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP installed on the remote
host is 5.3.x prior to 5.3.29. It is, therefore, affected by the
following vulnerabilities :

  - A heap-based buffer overflow error exists in the file
    'ext/date/lib/parse_iso_intervals.c' related to handling
    DateInterval objects that allows denial of service
    attacks. (CVE-2013-6712)

  - A boundary checking error exists related to the Fileinfo
    extension, Composite Document Format (CDF) handling, and
    the function 'cdf_read_short_sector'. (CVE-2014-0207)

  - A flaw exists with the 'cdf_unpack_summary_info()'
    function within 'src/cdf.c' where multiple file_printf
    calls occur when handling specially crafted CDF files.
    This could allow a context dependent attacker to crash
    the web application using PHP. (CVE-2014-0237)

  - A flaw exists with the 'cdf_read_property_info()'
    function within 'src/cdf.c' where an infinite loop
    occurs when handling specially crafted CDF files. This
    could allow a context dependent attacker to crash the
    web application using PHP. (CVE-2014-0238)

  - A type-confusion error exists related to the Standard
    PHP Library (SPL) extension and the function
    'unserialize'. (CVE-2014-3515)

  - An error exists related to configuration scripts and
    temporary file handling that could allow insecure file
    usage. (CVE-2014-3981)

  - A heap-based buffer overflow error exists related to the
    function 'dns_get_record' that could allow execution of
    arbitrary code. (CVE-2014-4049)

  - An out-of-bounds read exists in printf. (Bug #67249)

Note that Nessus has not attempted to exploit these issues, but has
instead relied only on the application's self-reported version number.

Additionally, note that version 5.3.29 marks the end of support for
the PHP 5.3.x branch.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/archive/2014.php#id2014-08-14-1");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.3.29");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 5.3.29 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

version = php["ver"];
source = php["src"];

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

# Check that it is the correct version of PHP
if (version =~ "^5(\.3)?$") audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^5\.3\.") audit(AUDIT_NOT_DETECT, "PHP version 5.3.x", port);

if (version =~ "^5\.3\.([0-9]|[1][0-9]|2[0-8])($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : '+source +
      '\n  Installed version : '+version+
      '\n  Fixed version     : 5.3.29\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
