#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17713);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/11/14 18:42:58 $");

  script_cve_id(
    "CVE-2006-1017",
    "CVE-2006-4020",
    "CVE-2006-4481",
    "CVE-2006-4482",
    "CVE-2006-4483",
    "CVE-2006-4484",
    "CVE-2006-4485"
  );
  script_bugtraq_id(16878, 19415, 19582);
  script_osvdb_id(
    23535,
    27824,
    27999,
    28002,
    28003,
    28004,
    28007,
    28009,
    28717
  );

  script_name(english:"PHP 5.1.x < 5.1.5 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");
 
  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of PHP 5.x installed on the
remote host is older than 5.1.5.  Such versions may be affected by the
following vulnerabilities :

  - The c-client library 2000, 2001, or 2004 for PHP does
    not check the safe_mode or open_basedir functions.
    (CVE-2006-1017)

  - A buffer overflow exists in the sscanf function.
    (CVE-2006-4020)

  - The file_exists and imap_reopen functions do not check
    for the safe_mode and open_basedir settings, which 
    allows local users to bypass the settings. 
    (CVE-2006-4481)

  - Multiple heap-based buffer overflows exist in the
    str_repeat and wordwrap functions in 
    ext/standard/string.c. (CVE-2006-4482)

  - The cURL extension files permit the
    CURLOPT_FOLLOWLOCATION option when open_basedir or
    safe_mode is enabled, which allows attackers to perform
    unauthorized actions. (CVE-2006-4483)

  - A buffer overflow vulnerability exists in the
    LWZReadByte_ function in ext/gd/libgd/gd_gif_in.c in the
    GD extension. (CVE-2006-4484)

  - The stripos function is affected by an out-of-bounds
    read. (CVE-2006-4485)"
  );
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=38322");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/5_1_5.php");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 5.1.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

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

if (version =~ "^5\.(0\.|1\.[0-4]([^0-9]|$))")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.1.5\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
