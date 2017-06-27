#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39480);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/10/23 20:09:34 $");

  script_cve_id("CVE-2009-2687");
  script_bugtraq_id(35440, 35435);
  script_osvdb_id(55222, 55223, 55224);
  script_xref(name:"Secunia", value:"35441");

  script_name(english:"PHP < 5.2.10 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities.");

 script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP installed on the remote
host is older than 5.2.10.  Such versions are reportedly affected by
multiple vulnerabilities :

  - Sufficient checks are not performed on fields reserved 
    for offsets in function 'exif_read_data()'. Successful 
    exploitation of this issue could result in a denial of 
    service condition. (bug 48378)

  - Provided 'safe_mode_exec_dir' is not set (not set by
    default), it may be possible to bypass 'safe_mode' 
    restrictions by preceding a backslash in functions 
    such as 'exec()', 'system()', 'shell_exec()', 
    'passthru()' and 'popen()' on a system running PHP 
    on Windows. (bug 45997)");

  script_set_attribute(attribute:"see_also", value:
"http://bugs.php.net/bug.php?id=45997");
  script_set_attribute(attribute:"see_also", value:
"http://bugs.php.net/bug.php?id=48378");
  script_set_attribute(attribute:"see_also", value:
"http://www.php.net/releases/5_2_10.php");
  script_set_attribute(attribute:"see_also", value:
"http://www.php.net/ChangeLog-5.php#5.2.10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.2.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");

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
    version =~ "^5\.2\.[0-9]($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.2.10\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
