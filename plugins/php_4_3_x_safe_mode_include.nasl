#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(11807);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2013/10/23 20:09:34 $");

  script_cve_id("CVE-2003-0863");
  script_bugtraq_id(8201);
  script_osvdb_id(11669);

  script_name(english:"PHP < 4.3.3 php_check_safe_mode_include_dir Function Safemode Bypass");
  script_summary(english:"Checks for version of PHP");

  script_set_attribute(
    attribute:"synopsis",
    value:"Arbitrary files may be read on the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of PHP 4.3.x installed on the
remote host is prior to 4.3.2.   It is, therefore, potentially
affected by an information disclosure vulnerability.

Due to a flaw in the function php_safe_mode_include_dir(), a local
attacker could bypass safe mode and gain unauthorized access to
files on the local system."
  );
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP 4.3.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2003/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/07/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2013 Tenable Network Security, Inc.");

  script_dependencie("php_version.nasl");
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

if (version =~ "^4\.3\.[0-2]($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 4.3.3\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
