#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66584);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/30 16:53:17 $");

  script_cve_id("CVE-2013-1824");
  script_bugtraq_id(62373);
  script_osvdb_id(90922);

  script_name(english:"PHP 5.3.x < 5.3.23 Information Disclosure");
  script_summary(english:"Checks version of PHP");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server uses a version of PHP that is potentially
affected by an information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of PHP 5.3.x installed on the
remote host is prior to 5.3.23.  It is, therefore, potentially affected
by an information disclosure vulnerability. 

The fix for CVE-2013-1643 was incomplete and an error still exists in
the files 'ext/soap/php_xml.c' and 'ext/libxml/libxml.c' related to
handling external entities.  This error could cause PHP to parse remote
XML documents defined by an attacker and could allow access to arbitrary
files. 

Note that this plugin does not attempt to exploit the vulnerability, but
instead relies only on PHP's self-reported version number."
  );
  # Fixes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c770707");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.3.23");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 5.3.23 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
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

# Check that it is the correct version of PHP
if (version =~ "^5(\.3)?$") exit(1, "The banner from the PHP install associated with port "+port+" - "+version+" - is not granular enough to make a determination.");
if (version !~ "^5\.3\.") audit(AUDIT_NOT_DETECT, "PHP version 5.3.x", port);

if (version =~ "^5\.3\.([0-9]|1[0-9]|2[0-2])($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : '+source +
      '\n  Installed version : '+version+
      '\n  Fixed version     : 5.3.23\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
