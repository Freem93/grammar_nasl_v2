#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57537);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/02 14:37:08 $");

  script_cve_id(
    "CVE-2011-3379",
    "CVE-2011-4566",
    "CVE-2011-4885",
    "CVE-2012-0057",
    "CVE-2012-0781",
    "CVE-2012-0788",
    "CVE-2012-0789"
  );
  script_bugtraq_id(49754, 50907, 51193, 51806, 51952, 51992, 52043);
  script_osvdb_id(75713, 77446, 78115, 78571, 78676, 79016, 79332);
  script_xref(name:"TRA", value:"TRA-2012-01");

  script_name(english:"PHP < 5.3.9 Multiple Vulnerabilities");
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
host is older than 5.3.9.  As such, it may be affected by the following
security issues :

  - The 'is_a()' function in PHP 5.3.7 and 5.3.8 triggers a 
    call to '__autoload()'. (CVE-2011-3379)

  - It is possible to create a denial of service condition 
    by sending multiple, specially crafted requests 
    containing parameter values that cause hash collisions 
    when computing the hash values for storage in a hash 
    table.  (CVE-2011-4885)
   
  - An integer overflow exists in the exif_process_IFD_TAG 
    function in exif.c that can allow a remote attacker to 
    read arbitrary memory locations or cause a denial of 
    service condition.  This vulnerability only affects PHP 
    5.4.0beta2 on 32-bit platforms. (CVE-2011-4566)

  - Calls to libxslt are not restricted via
    xsltSetSecurityPrefs(), which could allow an attacker
    to create or overwrite files, resulting in arbitrary
    code execution. (CVE-2012-0057)

  - An error exists in the function 'tidy_diagnose' that
    can allow an attacker to cause the application to 
    dereference a NULL pointer. This causes the application
    to crash. (CVE-2012-0781)

  - The 'PDORow' implementation contains an error that can
    cause application crashes when interacting with the 
    session feature. (CVE-2012-0788)

  - An error exists in the timezone handling such that
    repeated calls to the function 'strtotime' can allow
    a denial of service attack via memory consumption.
    (CVE-2012-0789)"
  );
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2012-01");
  script_set_attribute(attribute:"see_also", value:"http://xhe.myxwiki.org/xwiki/bin/view/XSLT/Application_PHP5");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/archive/2012.php#id2012-01-11-1");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Jan/91");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=55475");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=55776");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=53502");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.3.9");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to PHP version 5.3.9 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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

if (
  version =~ "^[0-4]\." || 
  version =~ "^5\.[0-2]\." ||
  version =~ "^5\.3\.[0-8]($|[^0-9])" ||
  version =~ "^5\.4\.0(alpha|beta)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.3.9\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
