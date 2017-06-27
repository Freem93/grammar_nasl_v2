#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31649);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_cve_id(
    "CVE-2006-1015",
    "CVE-2006-1549",
    "CVE-2006-2660",
    "CVE-2006-4486",
    "CVE-2006-4625",
    "CVE-2006-4812",
    "CVE-2006-5465",
    "CVE-2006-5706",
    "CVE-2006-7205",
    "CVE-2007-0448",
    "CVE-2007-1381",
    "CVE-2007-1584",
    "CVE-2007-1888",
    "CVE-2007-2844",
    "CVE-2007-5424"
  );
  script_bugtraq_id(20349, 20879, 49634);
  script_osvdb_id(
    24485,
    24945,
    25270,
    27080,
    28001,
    29510,
    29603,
    30178,
    30179,
    32775,
    33928,
    33939,
    33951,
    36088,
    39177,
    43674
  );

  script_name(english:"PHP 5.x < 5.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");
 
  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server uses a version of PHP that is affected by
multiple buffer overflows."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of PHP 5.x installed on the
remote host is older than 5.2.  Such versions may be affected by
several buffer overflows. 

To exploit these issues, an attacker would need the ability to upload
an arbitrary PHP script on the remote server or to manipulate several
variables processed by some PHP functions such as 'htmlentities().'"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/advisory_092006.133.html");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/5_2_0.php");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 5.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94, 119, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

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

if (version !~ "^5\.") exit(0, "The web server on port "+port+" uses PHP "+version+" rather than 5.x.");

if (version =~ "^5\.[0-1]\.")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.2\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
