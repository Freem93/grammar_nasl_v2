#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58988);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_cve_id("CVE-2012-1823");
  script_bugtraq_id(53388);
  script_osvdb_id(81633, 82213);
  script_xref(name:"CERT", value:"520827");

  script_name(english:"PHP < 5.3.12 / 5.4.2 CGI Query String Code Execution");
  script_summary(english:"Checks version of PHP");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server uses a version of PHP that is affected by a
remote code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of PHP installed on the remote
host is earlier than 5.3.12 / 5.4.2, and as such is potentially
affected by a remote code execution and information disclosure
vulnerability. 

An error in the file 'sapi/cgi/cgi_main.c' can allow a remote attacker
to obtain PHP source code from the web server or to potentially
execute arbitrary code.  In vulnerable configurations, PHP treats
certain query string parameters as command line arguments including
switches such as '-s', '-d', and '-c'. 

Note that this vulnerability is exploitable only when PHP is used in
CGI-based configurations.  Apache with 'mod_php' is not an exploitable
configuration."
  );
  script_set_attribute(attribute:"see_also", value:"http://eindbazen.net/2012/05/php-cgi-advisory-cve-2012-1823/");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=61910");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/archive/2012.php#id2012-05-03-1");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.3.12");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.4.2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.3.12 / 5.4.2 or later.  A 'mod_rewrite'
workaround is available as well.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP CGI Argument Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/04");

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

if (
  version =~ "^[0-4]\." ||
  version =~ "^5\.[0-2]($|[^0-9])" ||
  version =~ "^5\.3\.([0-9]|1[01])($|[^0-9])" ||
  version =~ "^5\.4\.[01]($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.3.12 / 5.4.2\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
