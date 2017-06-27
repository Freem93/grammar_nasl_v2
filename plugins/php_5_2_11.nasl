#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41014);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_cve_id(
    "CVE-2009-3291",
    "CVE-2009-3292",
    "CVE-2009-3293",
    "CVE-2009-3294",
    "CVE-2009-4018",
    "CVE-2009-5016"
  );
  script_bugtraq_id(36449, 44889);
  script_osvdb_id(58185, 58186, 58187, 58188, 60438, 69227);
  script_xref(name:"Secunia", value:"36791");

  script_name(english:"PHP < 5.2.11 Multiple Vulnerabilities");
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
"According to its banner, the version of PHP installed on the remote
host is older than 5.2.11.  Such versions may be affected by several
security issues :

  - An unspecified error occurs in certificate validation
    inside 'php_openssl_apply_verification_policy'.

  - An unspecified input validation vulnerability affects
    the color index in 'imagecolortransparent()'.

  - An unspecified input validation vulnerability affects
    exif processing.

  - Calling 'popen()' with an invalid mode can cause a
    crash under Windows. (Bug #44683)

  - An integer overflow in 'xml_utf8_decode()' can make it
    easier to bypass cross-site scripting and SQL injection 
    protection mechanisms using a specially crafted string 
    with a long UTF-8 encoding. (Bug #49687)

  - 'proc_open()' can bypass 'safe_mode_protected_env_vars'.
    (Bug #49026)"
  );

  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/ChangeLog-5.php#5.2.11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/releases/5_2_11.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://news.php.net/php.internals/45597"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/ChangeLog-5.php#5.2.11"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to PHP version 5.2.11 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 134, 264);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

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

if (version =~ "^[0-4]\." || 
    version =~ "^5\.[01]\." || 
    version =~ "^5\.2\.([0-9]|10)($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.2.11\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
