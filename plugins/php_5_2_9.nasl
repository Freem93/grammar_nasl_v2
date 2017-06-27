#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35750);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_cve_id("CVE-2008-5498", "CVE-2009-1271", "CVE-2009-1272");
  script_bugtraq_id(33002, 33927);
  script_osvdb_id(51031, 52486, 53440);
  script_xref(name:"Secunia", value:"34081");

  script_name(english:"PHP < 5.2.9 Multiple Vulnerabilities");
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
host is older than 5.2.9.  Such versions may be affected by several
security issues :

  - Background color is not correctly validated with a non true
    color image in function 'imagerotate()'. (CVE-2008-5498)

  - A denial of service condition can be triggered by trying to 
    extract zip files that contain files with relative paths 
    in file or directory names.

  - Function 'explode()' is affected by an unspecified 
    vulnerability.

  - It may be possible to trigger a segfault by passing a 
    specially crafted string to function 'json_decode()'.

  - Function 'xml_error_string()' is affected by a flaw
    which results in messages being off by one."
  );
  script_set_attribute(attribute:"see_also", value:
"http://news.php.net/php.internals/42762");
  script_set_attribute(attribute:"see_also", value:
"http://www.php.net/releases/5_2_9.php");
  script_set_attribute(attribute:"see_also", value:
"http://www.php.net/ChangeLog-5.php#5.2.9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.2.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 200);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include('misc_func.inc');
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

if (version =~ "^[0-4]\." ||
    version =~ "^5\.[01]\." ||
    version =~ "^5\.2\.[0-8]($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.2.9\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
