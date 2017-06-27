#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28181);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_cve_id(
    "CVE-2007-3996",
    "CVE-2007-4782",
    "CVE-2007-4783",
    "CVE-2007-4784",
    "CVE-2007-4825",
    "CVE-2007-4840",
    "CVE-2007-4887",
    "CVE-2007-4889",
    "CVE-2007-5447",
    "CVE-2007-5653",
    "CVE-2007-5898",
    "CVE-2007-5899",
    "CVE-2007-5900",
    "CVE-2008-2107",
    "CVE-2008-2108",
    "CVE-2008-4107"
  );
  script_bugtraq_id(26403, 69246);
  script_osvdb_id(
    36870,
    37784,
    38680,
    38681,
    38682,
    38683,
    38684,
    38685,
    38686,
    38687,
    38688,
    38916,
    38917,
    38918,
    41708,
    41775,
    44909,
    44910,
    45902,
    49561
  );

  script_name(english:"PHP < 5.2.5 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");
 
  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server uses a version of PHP that is affected by
multiple flaws."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of PHP installed on the remote
host is older than 5.2.5.  Such versions may be affected by various
issues, including but not limited to several buffer overflows."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/5_2_5.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 22, 78, 94, 189, 200, 264);

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

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

if (version =~ "^5\.[01]\." ||
    version =~ "^5\.2\.[0-4]($|[^0-9])"
) 
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.2.5\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
