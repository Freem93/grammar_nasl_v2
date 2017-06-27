#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17796);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/10/23 20:09:34 $");

  script_cve_id("CVE-2006-4812");
  script_bugtraq_id(20349);
  script_osvdb_id(29510);

  script_name(english:"PHP 4.x < 4.3.0 ZendEngine Integer Overflow");
  script_summary(english:"Checks version of PHP");

  script_set_attribute(
    attribute:"synopsis",
    value:"Arbitrary code may be run on the remote server."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of PHP 4.x older than 4.3.0.  As
such, it reportedly has an integer overflow in array creation that can
be triggered by user-input passed to an 'unserialize()' function. 

Successful exploitation of this vulnerability could allow an attacker
to execute arbitrary code on this host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/advisory_092006.133.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP 4.3.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/11");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/05");

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

if (version !~ "^4\.") exit(0, "The web server on port "+port+" uses PHP "+version+" rather than 4.x.");

if (version =~ "^4\.[0-2]\.")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 4.3.0\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
