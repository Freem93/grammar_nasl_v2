#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22268);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/05/16 14:22:05 $");

  script_cve_id(
    "CVE-2006-0996",
    "CVE-2006-1490", 
    "CVE-2006-1494", 
    "CVE-2006-1608",
    "CVE-2006-1990",
    "CVE-2006-1991",
    "CVE-2006-2563",
    "CVE-2006-2660",
    "CVE-2006-3011",
    "CVE-2006-3016", 
    "CVE-2006-3017", 
    "CVE-2006-3018",
    "CVE-2006-4433"
  );
  script_bugtraq_id(17296, 17362, 17439, 17843, 18116, 18645, 49634);
  script_osvdb_id(
    24248,
    24484,
    24486,
    24487,
    24944,
    24946,
    25253,
    25254,
    25255,
    25813,
    26466,
    26827,
    27080,
    28006,
    28233,
    28273
  );

  script_name(english:"PHP < 4.4.3 / 5.1.4 Multiple Vulnerabilities");
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
host is older than 4.4.3 / 5.1.4.  Such versions may be affected by
several issues, including a buffer overflow, heap corruption, and a
flaw by which a variable may survive a call to 'unset()'."
  );
  # http://www.securityfocus.com/archive/1/20060409192313.20536.qmail@securityfocus.com
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11971b3d");
  # http://www.hardened-php.net/hphp/zend_hash_del_key_or_index_vulnerability.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ccaf872d");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/442437/100/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/release_4_4_3.php");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/release_5_1_3.php");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/release_5_1_4.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 4.4.3 / 5.1.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

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

if (version =~ "^3\." ||
    version =~ "^4\.([0-3]\.|4\.[0-2]($|[^0-9]))" ||
    version =~ "^5\.(0\.|1\.[0-3]($|[^0-9]))"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 4.4.3 / 5.1.4\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
