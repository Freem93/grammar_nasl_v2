#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(15436);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2013/10/23 20:09:34 $");

  script_cve_id("CVE-2004-0958");
  script_bugtraq_id(11334);
  script_osvdb_id(12601);

  script_name(english:"PHP php_variables.c Multiple Variable Open Bracket Memory Disclosure");
  script_summary(english:"Checks for version of PHP");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote server is affected by an information disclosure 
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of PHP that is older than 5.0.2 
or 4.39.

The remote version of this software is affected by a memory disclosure
vulnerability in PHP_Variables.  An attacker may exploit this flaw to
remotely read portions of the memory of the httpd process on the
remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.0.2");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP 5.0.2 or 4.3.9.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/08");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:php:php");
  script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

#
# The script code starts here
#

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

if (version =~ "^[0-3]\." ||
    version =~ "^4\.[0-2]\." ||
    version =~ "^4\.3\.[0-8]($|[^0-9])" ||
    version =~ "^5\.0\.[01]($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.0.2 / 4.3.9\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
