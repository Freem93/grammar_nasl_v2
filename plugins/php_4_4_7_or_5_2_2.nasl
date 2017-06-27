#
# Copyright (C) Westpoint Limited
#
# Based on scripts written by Tenable Network Security.
#
# Changes made by Tenable:
# -Add audit.inc include and adjust get_kb_item code to obtain
# PHP version and source after updates to php_version.nasl (9/5/2013)
#


include("compat.inc");

if(description)
{
  script_id(25159);
  script_version("$Revision: 1.36 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_cve_id(
    "CVE-2007-0455",
    "CVE-2007-0911",
    "CVE-2007-1001",
    "CVE-2007-1521",
    "CVE-2007-1285",
    "CVE-2007-1375",
    "CVE-2007-1396",
    "CVE-2007-1399",
    "CVE-2007-1460",
    "CVE-2007-1461",
    "CVE-2007-1484",
    "CVE-2007-1522",
    "CVE-2007-1582",
    "CVE-2007-1583",
    "CVE-2007-1709",
    "CVE-2007-1710",
    "CVE-2007-1717",
    "CVE-2007-1718",
    "CVE-2007-1864",
    "CVE-2007-1883",
    "CVE-2007-2509",
    "CVE-2007-2510",
    "CVE-2007-2511",
    "CVE-2007-2727",
    "CVE-2007-2748",
    "CVE-2007-3998",
    "CVE-2007-4670"
  );
  script_bugtraq_id(
    22289,
    22764,
    22990,
    23357,
    23813,
    23818,
    23984,
    24012
  );
  script_osvdb_id(
    32769,
    32780,
    32782,
    33008,
    33934,
    33935,
    33936,
    33937,
    33938,
    33940,
    33941,
    33948,
    33952,
    33954,
    34671,
    34672,
    34673,
    34674,
    34675,
    34676,
    34730,
    35165,
    36087,
    36206,
    36858,
    36863
  );

  script_name(english:"PHP < 4.4.7 / 5.2.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple flaws.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP installed on the remote
host is older than 4.4.7 / 5.2.2.  Such versions may be affected by
several issues, including buffer overflows in the GD library.");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/4_4_7.php");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/5_2_2.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP 4.4.7 / 5.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/04");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Westpoint Limited.");

  script_dependencies("php_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "Settings/ParanoidReport");
  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");

# Banner checks of PHP are prone to false-positives so we only run the
# check if the reporting is paranoid.
if (report_paranoia <= 1) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

version = get_kb_item_or_exit('www/php/'+port+'/version');
match = eregmatch(string:version, pattern:'(.+) under (.+)$');
if (!isnull(match))
{
  version = match[1];
  source = match[2];
}

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');
if (report_paranoia < 2 && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

if (version =~ "^3\.|4\.[0-3]\." ||
    version =~ "^4\.4\.[0-6]($|[^0-9])" ||
    version =~ "^5\.[01]\." ||
    version =~ "^5\.2\.[01]($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 4.4.7 / 5.2.2\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
