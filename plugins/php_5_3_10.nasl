#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57825);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/10/23 20:09:34 $");

  script_cve_id("CVE-2012-0830");
  script_bugtraq_id(51830);
  script_osvdb_id(78819);

  script_name(english:"PHP 5.3.9 'php_register_variable_ex()' Code Execution (banner check)");
  script_summary(english:"Checks version of PHP");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server uses a version of PHP that is affected by a
code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of PHP installed on the remote
host is 5.3.9.  This version reportedly is affected by a code
execution vulnerability. 

Specifically, the fix for the hash collision denial of service
vulnerability (CVE-2011-4885) itself has introduced a remote code
execution vulnerability in the function 'php_register_variable_ex()' in
the file 'php_variables.c'.  A new configuration variable,
'max_input_vars', was added as a part of the fix.  If the number of
input variables exceeds this value and the variable being processed is
an array, code execution can occur."
  );
  script_set_attribute(attribute:"see_also", value:"https://gist.github.com/1725489");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.3.10");
  # http://thexploit.com/sec/critical-php-remote-vulnerability-introduced-in-fix-for-php-hashtable-collision-dos/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1ee2de8");
  script_set_attribute(attribute:"see_also", value:"http://svn.php.net/viewvc?view=revision&revision=323007");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 5.3.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

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

if (version =~ "^5\.3\.9($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.3.10\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
