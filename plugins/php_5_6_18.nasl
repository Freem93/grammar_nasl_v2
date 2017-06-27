#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88694);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/06/20 20:49:18 $");

  script_cve_id(
    "CVE-2015-8383",
    "CVE-2015-8386",
    "CVE-2015-8387",
    "CVE-2015-8389",
    "CVE-2015-8390",
    "CVE-2015-8391",
    "CVE-2015-8393",
    "CVE-2015-8394"
  );
  script_bugtraq_id(
    79810,
    82990
  );
  script_osvdb_id(
    131055,
    131059,
    131060,
    131062,
    131063,
    131064,
    131066,
    131067,
    134028,
    134029,
    134030,
    134031,
    134032,
    134033,
    134034
  );

  script_name(english:"PHP 5.6.x < 5.6.18 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 5.6.x prior to 5.6.18. It is, therefore, affected by
multiple vulnerabilities :

  - The Perl-Compatible Regular Expressions (PCRE) library
    is affected by multiple vulnerabilities related to the
    handling of regular expressions, subroutine calls, and
    binary files. A remote attacker can exploit these to
    cause a denial of service, obtain sensitive information,
    or have other unspecified impact. (CVE-2015-8383,
    CVE-2015-8386, CVE-2015-8387, CVE-2015-8389,
    CVE-2015-8390, CVE-2015-8391, CVE-2015-8393,
    CVE-2015-8394)

  - A flaw exists in file ext/standard/exec.c in the
    escapeshellcmd() and escapeshellarg() functions due to
    the program truncating NULL bytes in strings. A remote
    attacker can exploit this to bypass restrictions.
    (VulnDB 134028)

  - A flaw exists in file ext/standard/streamsfuncs.c in the
    stream_get_meta_data() function due to a failure to
    restrict writing user-supplied data to fields not
    already set. A remote attacker can exploit this to
    falsify the output of the function, resulting in the
    insertion of malicious metadata. (VulnDB 134029)

  - A type confusion error exists in file ext/wddx/wddx.c in
    the php_wddx_pop_element() function when deserializing
    WDDX packets. A remote attacker can exploit this to have
    an unspecified impact. (VulnDB 134030)

  - A flaw exists in file ext/phar/phar_object.c in the
    PharFileInfo::getContent() method due to the use of
    uninitialized memory causing improper validation of
    user-supplied input. A remote attacker can exploit this
    to corrupt memory, resulting in a denial of service or
    the execution of arbitrary code. (VulnDB 134031)

  - A NULL pointer dereference flaw exists in file
    ext/phar/tar.c in the phar_tar_setupmetadata() function
    when parsing metadata from a crafted TAR file. A remote
    attacker can exploit this to cause a denial of service.
    (VulnDB 134032)

  - An integer overflow condition exists in file
    ext/standard/iptc.c in the iptcembed() function due to
    improper validation of user-supplied input. A remote
    attacker can exploit this to cause a heap-based buffer
    overflow, resulting in a denial of service or the
    execution of arbitrary code. (VulnDB 134033)

  - An overflow condition exists in file ext/phar/tar.c in
    the phar_parse_tarfile() function due to improper
    validation of user-supplied input when decompressing
    TAR files. A remote attacker can exploit this to cause
    a stack-based buffer overflow, resulting in a denial of
    service or the execution of arbitrary code.
    (VulnDB 134034)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.6.18");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.6.18 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/11");

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

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

# Check that it is the correct version of PHP
if (version =~ "^5(\.6)?$") audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^5\.6\.") audit(AUDIT_NOT_DETECT, "PHP version 5.6.x", port);

if (version =~ "^5\.6\.([0-9]|1[0-7])($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : '+source +
      '\n  Installed version : '+version +
      '\n  Fixed version     : 5.6.18' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
