#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17709);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/02/11 15:08:19 $");

  script_cve_id("CVE-2006-0208");
  script_osvdb_id(22480);

  script_name(english:"PHP < 4.4.2 Multiple XSS Vulnerabilities");
  script_summary(english:"Checks version of PHP");
 
  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server uses a version of PHP that is affected by
multiple cross-site scripting vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of PHP installed on the remote
host is older than 4.4.2.  Such versions are potentially affected by
multiple cross-site scripting vulnerabilities when display_errors and
html_errors are on."
  );

  script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/4_4_2.php");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 4.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

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

if (
  version =~ "^3\." ||
  version =~ "^4\.([0-3]\.|4\.[01]([^0-9]|$))"
)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 4.4.2\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
