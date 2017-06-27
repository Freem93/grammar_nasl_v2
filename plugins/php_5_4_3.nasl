#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59057);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/08/19 13:38:50 $");

  script_cve_id(
    "CVE-2012-2311",
    "CVE-2012-2329",
    "CVE-2012-2335",
    "CVE-2012-2336"
  );
  script_bugtraq_id(53388, 53455);
  script_osvdb_id(81633, 82213, 82215);
  script_xref(name:"CERT", value:"520827");

  script_name(english:"PHP 5.4.x < 5.4.3 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of PHP installed on the remote
host is 5.4.x earlier than 5.4.3. It is, therefore, potentially
affected the following vulnerabilities : 

  - The fix for CVE-2012-1823 does not completely correct
    the CGI query parameter vulnerability. Disclosure of
    PHP source code and code execution are still possible.
    Note that this vulnerability is exploitable only when
    PHP is used in CGI-based configurations.  Apache with
    'mod_php' is not an exploitable configuration.
    (CVE-2012-2311, CVE-2012-2335, CVE-2012-2336)

  - An unspecified buffer overflow exists related to the
    function 'apache_request_headers'. (CVE-2012-2329)"
  );
  script_set_attribute(attribute:"see_also", value:"http://eindbazen.net/2012/05/php-cgi-advisory-cve-2012-1823/");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=61910");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/archive/2012.php#id2012-05-08-1");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.4.3");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 5.4.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP apache_request_headers Function Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/09");

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
include("audit.inc");
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

if (version =~ "^5\.4\.[0-2]($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.4.3\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
