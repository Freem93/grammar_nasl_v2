#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51140);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/16 14:22:05 $");

  script_cve_id(
    "CVE-2006-7243",
    "CVE-2010-2094",
    "CVE-2010-2950",
    "CVE-2010-3436",
    "CVE-2010-3709",
    "CVE-2010-3710",
    "CVE-2010-3870",
    "CVE-2010-4150",
    "CVE-2010-4156",
    "CVE-2010-4409",
    "CVE-2010-4697",
    "CVE-2010-4698",
    "CVE-2010-4699",
    "CVE-2010-4700",
    "CVE-2011-0753",
    "CVE-2011-0754",
    "CVE-2011-0755"
  );
  script_bugtraq_id(
    40173,
    43926,
    44605,
    44718,
    44723,
    44951,
    44980,
    45119,
    45335,
    45338,
    45339,
    45952,
    45954,
    46056,
    46168
  );
  script_osvdb_id(
    66086,
    68597,
    69099,
    69109,
    69110,
    69230,
    69651,
    69660,
    70606,
    70607,
    70608,
    70609,
    70610,
    74193,
    74688,
    74689
  );
  script_xref(name:"CERT", value:"479900");

  script_name(english:"PHP 5.3 < 5.3.4 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server uses a version of PHP that is affected by
multiple flaws."
  );

  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of PHP 5.3 installed on the
remote host is older than 5.3.4.  Such versions may be affected by
several security issues :

  - A crash in the zip extract method.

  - A stack-based buffer overflow in impagepstext()
    of the GD extension.

  - An unspecified vulnerability related to
    symbolic resolution when using a DFS share.

  - A security bypass vulnerability related
    to using pathnames containing NULL bytes.
    (CVE-2006-7243)

  - Multiple format string vulnerabilities.
    (CVE-2010-2094, CVE-2010-2950)

  - An unspecified security bypass vulnerability
    in open_basedir(). (CVE-2010-3436)

  - A NULL pointer dereference in
    ZipArchive::getArchiveComment. (CVE-2010-3709)

  - Memory corruption in php_filter_validate_email().
    (CVE-2010-3710)

  - An input validation vulnerability in
    xml_utf8_decode(). (CVE-2010-3870)

  - A possible double free in the IMAP extension.
    (CVE-2010-4150)

  - An information disclosure vulnerability in
    'mb_strcut()'. (CVE-2010-4156)

  - An integer overflow vulnerability in 'getSymbol()'.
    (CVE-2010-4409)

  - A use-after-free vulnerability in the Zend engine when
    a '__set()', '__get()', '__isset()' or '__unset()'
    method is called can allow for a denial of service
    attack. (Bug #52879 / CVE-2010-4697)

  - A stack-based buffer overflow exists in the
    'imagepstext()' function in the GD extension. (Bug
    #53492 / CVE-2010-4698)

  - The 'iconv_mime_decode_headers()' function in the iconv
    extension fails to properly handle encodings that are
    not recognized by the iconv and mbstring
    implementations. (Bug #52941 / CVE-2010-4699)

  - The 'set_magic_quotes_runtime()' function when the
    MySQLi extension is used does not properly interact
    with the 'mysqli_fetch_assoc()' function. (Bug #52221 /
    CVE-2010-4700)

  - A race condition exists in the PCNTL extension.
    (CVE-2011-0753)

  - The SplFileInfo::getType function in the Standard PHP
    Library extension does not properly detect symbolic
    links. (CVE-2011-0754)

  - An integer overflow exists in the mt_rand function.
    (CVE-2011-0755)"
  );

  script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/5_3_4.php");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.3.4");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP 5.3.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
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

if (version =~ "^5\.3\.[0-3]($|[^0-9])") 
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.3.4\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
