#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17711);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/11 21:07:50 $");

  script_cve_id("CVE-2005-3319", "CVE-2005-3883");
  script_bugtraq_id(15177, 15571);
  script_osvdb_id(20491, 21239, 66493);

  script_name(english:"PHP 5.x < 5.1.0 Multiple Vulnerabilities");
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
"According to its banner, the version of PHP 5.x installed on the 
remote host is older than 5.1.0.  Such versions may be affected by 
multiple vulnerabilities :

  - A cross-site scripting vulnerability exists in 
    phpinfo().

  - Multiple safe_mode/open_basedir bypass vulnerabilities
    exist in ext/curl and ext/gd.

  - It is possible to overwrite $GLOBALS due to an issue in
    file upload handling, extract(), and 
    import_request_variables().

  - An issue exists when a request is terminated due to 
    memory_limit constraints during certain parse_str() 
    calls, which could lead to register globals being turned
    on.

  - An issue exists with trailing slashes in allowed 
    basedirs.

  - An issue exists with calling virtual() on Apache 2, which 
    allows an attacker to bypass certain configuration 
    directives like safe_mode or open_basedir.

  - A possible header injection exists in the mb_send_mail()
    function.
    
  - The apache2handler SAPI in the Apache module allows 
    attackers to cause a denial of service."
  );

  script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/5_1_0.php");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 5.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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

if (version =~ "^5\.0")
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.1.0\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
