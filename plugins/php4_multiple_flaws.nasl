#
# (C) Tenable Network Security, Inc.
#

# Ref:
# http://www.securityfocus.com/advisories/5887
# http://www.php.net/ChangeLog-4.php
#


include("compat.inc");

if(description)
{
  script_id(11850);
  script_version("$Revision: 1.33 $");
  script_cvs_date("$Date: 2016/05/16 14:22:05 $");

  script_cve_id("CVE-2002-1396", "CVE-2003-0442", "CVE-2003-0860", "CVE-2003-0861");
  script_bugtraq_id(
    6488, 
    7761, 
    8693, 
    8696
  );
  script_osvdb_id(4758, 11667, 11668, 11670, 11671, 14530);
  script_xref(name:"RHSA", value:"2003:204-01");
  script_xref(name:"SuSE", value:"SUSE-SA:2003:0009");

  script_name(english:"PHP < 4.3.3 Multiple Vulnerabilities");
  script_summary(english:"Checks for version of PHP");

  script_set_attribute(
    attribute:"synopsis",
    value:"Arbitrary code may be run on the remote server."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of PHP that is older than 4.3.3.

All versions of PHP 4 older than 4.3.3 contain multiple integer
overflow vulnerabilities that may allow an attacker to execute
arbitrary commands on this host.  Another problem may also invalidate
safe_mode."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-4.php");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP 4.3.3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/09/24");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/12/27");
 
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

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

if (version =~ "^4\.[0-2]\." ||
    version =~ "^4\.3\.[0-2]($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 4.3.3\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
