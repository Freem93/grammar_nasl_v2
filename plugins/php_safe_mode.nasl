#
# (C) Tenable Network Security, Inc.
#

# References:
#
# Date: Fri, 23 Aug 2002 09:30:40 +0200 (CEST)
# From: "Wojciech Purczynski" <cliph@isec.pl>
# To: bugtraq@securityfocus.com
# Subject: PHP: Bypass safe_mode and inject ASCII control chars with mail()
# Message-ID:<Pine.LNX.4.44L.0208211118510.23552-100000@isec.pl>
#


include("compat.inc");

if(description)
{
  script_id(10701);
  script_version ("$Revision: 1.24 $");
  script_cvs_date("$Date: 2013/10/23 20:09:34 $");

  script_cve_id("CVE-2001-1246");
  script_bugtraq_id(2954);
  script_osvdb_id(579);
 
  script_name(english:"PHP Safe Mode mail Function 5th Parameter Arbitrary Command Execution");
  script_summary(english:"Checks for version of PHP");

  script_set_attribute(
    attribute:"synopsis",
    value:"Arbitrary commands may be run on the remote server.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running PHP 4.0.5.

There is a flaw in this version of PHP that allows local users to 
circumvent the safe mode and to gain the UID of the HTTP process."
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP 4.1.0.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2001/07/02");
  script_set_attribute(attribute:"vuln_publication_date", value:"2001/06/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2001-2013 Tenable Network Security, Inc.");

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

if (version =~ "^4\.0\.5($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 4.1.0\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
