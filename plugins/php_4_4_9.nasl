#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33849);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_cve_id(
    "CVE-2007-4850",
    "CVE-2008-3658",
    "CVE-2008-3659",
    "CVE-2008-3660",
    "CVE-2009-0754"
  );
  script_bugtraq_id(27413, 30649, 31612, 33542);
  script_osvdb_id(43219, 47796, 47797, 47798, 53574);
  script_xref(name:"Secunia", value:"31409");

  script_name(english:"PHP < 4.4.9 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");
 
  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server uses a version of PHP that is affected by
multiple issues."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of PHP installed on the remote
host is older than 4.4.9.  Such versions may be affected by several
security issues :

  - There are unspecified issues in the bundled PCRE library
    fixed by version 7.7.

  - A buffer overflow in the 'imageloadfont()' function in
    'ext/gd/gd.c' can be triggered when a specially crafted
    font is given. (CVE-2008-3658)

  - A buffer overflow exists in the internal 'memnstr()'
    function, which is exposed to userspace as 'explode()'.
    (CVE-2008-3659)

  - A denial of service vulnerability exists when a 
    filename contains 2 dots. (CVE-2008-3660)

  - An 'open_basedir' handling issue in the curl extension.

  - 'mbstring.func_overload' set in '.htaccess' becomes 
    global. (CVE-2009-0754)

Note that the release announcement states this will be the last
release for the PHP 4.4 series."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.openwall.com/lists/oss-security/2008/08/08/2");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/4_4_9.php");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-4.php#4.4.9");
  script_set_attribute(attribute:"see_also", value:"http://bugs.php.net/bug.php?id=27421");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 4.4.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 134, 264);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

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

if (version =~ "^3\." ||
    version =~ "^4\.[0-3]\." ||
    version =~ "^4\.4\.[0-8]($|[^0-9])"
)
{
if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 4.4.9\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
