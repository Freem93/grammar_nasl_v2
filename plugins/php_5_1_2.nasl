#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17712);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/16 14:22:05 $");

  script_cve_id("CVE-2006-0200", "CVE-2006-0207", "CVE-2006-0208");
  script_bugtraq_id(16220, 16803);
  script_osvdb_id(22478, 22479, 22480);

  script_name(english:"PHP 5.1.x < 5.1.2 Multiple Vulnerabilities");
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
"According to its banner, the version of PHP 5.1.x installed on the
remote host is older than 5.1.2.  Such versions may be affected by
multiple vulnerabilities :

  - A format string vulnerability exists in the 
    error-reporting feature of the mysqli extension.
    (CVE-2006-0200)

  - Multiple HTTP response splitting vulnerabilities exist
    that would allow remote attackers to inject arbitrary 
    HTTP headers via a crafted Set-Cookie header. 
    (CVE-2006-0207)

  - Multiple cross-site scripting vulnerabilities exist when
    display_errors and html_errors are on. (CVE-2006-0208)"
  );

  script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/5_1_2.php");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 5.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(134);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

if (version =~ "^5\.1\.[01]([^0-9]|$)")
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.1.2\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
