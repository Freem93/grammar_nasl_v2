#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35067);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_cve_id("CVE-2008-5814", "CVE-2008-5844");
  script_bugtraq_id(32673);
  script_osvdb_id(50587, 53532);

  script_name(english:"PHP < 5.2.8 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");
 
  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server uses a version of PHP that may be affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of PHP installed on the remote
host is earlier than 5.2.8.  As such, it is potentially affected by
the following vulnerabilities :

  - PHP fails to properly sanitize error messages of
    arbitrary HTML or script code, would code allow for 
    cross-site scripting attacks if PHP's 'display_errors' 
    setting is enabled. (CVE-2008-5814)

  - Version 5.2.7 introduced a regression with regard to
    'magic_quotes' functionality due to an incorrect fix to 
    the filter extension.  As a result, the 
    'magic_quotes_gpc' setting remains off even if it is set 
    to on. (CVE-2008-5844)"
  );
  script_set_attribute(attribute:"see_also", value:"http://bugs.php.net/42718");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/5_2_8.php");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 5.2.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 79);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/09");

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

if (
  version =~ "^[0-4]\." ||
  version =~ "^5\.[01]\." ||
  version =~ "^5\.2\.[0-7]($|[^0-9])"
)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.2.8\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
