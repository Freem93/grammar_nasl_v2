#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88679);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/06/23 20:35:54 $");

  script_cve_id("CVE-2016-1903", "CVE-2016-5114");
  script_bugtraq_id(79916);
  script_osvdb_id(
    132658,
    132659,
    132660,
    132661,
    132662,
    133626,
    133689
  );

  script_name(english:"PHP prior to 5.5.x < 5.5.31 / 5.6.x < 5.6.17 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PHP.");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote host
is 5.5.x prior to 5.5.31 or 5.6.x prior to 5.6.17. It is, therefore,
affected by multiple vulnerabilities :

  - An out-of-bounds read error exists in the
    gdImageRotateInterpolated() function in file
    gd_interpolation.c when handling background colors.
    A remote attacker can exploit this to disclose memory
    contents or crash the application. (CVE-2016-1903)

  - An unspecified flaw exists in file fpm_log.c in the
    fpm_log_write() function when handling very long
    HTTP requests. A local attacker can exploit this to
    obtain sensitive information, via access to the
    access log file. (CVE-2016-5114)

  - A use-after-free error exists in file wddx.c in the
    php_wddx_pop_element() function when handling WDDX
    packet deserialization. A remote attacker can exploit
    this, by dereferencing already freed memory, to execute
    arbitrary code. (VulnDB 132658)

  - A type confusion flaw exists in file xmlrpc-epi-php.c
    in the PHP_to_XMLRPC_worker() function. A remote
    attacker can exploit this to disclose memory contents,
    crash the application process, or have other impact.
    (VulnDB 132659)

  - A type confusion flaw exists in file wddx.c when
    handling WDDX packet deserialization. A remote attacker
    can exploit this to execute arbitrary code.
    (VulnDB 132660)

  - A flaw exists in file lsapilib.c when handling requests
    due to the LSAPI module failing to clear its secrets in
    child processes. A remote attacker can exploit this to
    gain access to memory contents, resulting in the
    disclosure of sensitive information. (VulnDB 133626)

  - A flaw exists in file lsapilib.c in the parseRequest()
    function due to a failure to properly sanitize input
    passed through multiple, unspecified parameters. A
    remote attacker can exploit this to cause a denial of
    service. (VulnDB 133689)");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.6.17");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.5.31");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.5.31 / 5.6.17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

if (version =~ "^5\.5\.([0-9]|[0-2][0-9]|30)($|[^0-9])" ||
    version =~ "^5\.6\.([0-9]|[0-1][0-6])($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.5.31 / 5.6.17\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
