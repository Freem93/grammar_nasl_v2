#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85886);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/06/20 20:49:18 $");

  script_cve_id(
    "CVE-2015-6834",
    "CVE-2015-6835",
    "CVE-2015-6836",
    "CVE-2015-6837",
    "CVE-2015-6838"
  );
  script_osvdb_id(127122);

  script_name(english:"PHP 5.5.x < 5.5.29 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 5.5.x prior to 5.5.29. It is, therefore, affected by the
following vulnerabilities :

  - Multiple use-after-free memory errors exist related to
    the unserialize() function. A remote attacker can
    exploit these errors to execute arbitrary code.
    (CVE-2015-6834)

  - A use-after-free memory error exists related to the
    php_var_unserialize() function. A remote attacker, using
    a crafted serialize string, can exploit this to execute
    arbitrary code. (CVE-2015-6835)

  - A type confusion error exists related to the
    serialize_function_call() function due to improper
    validation of the headers field. A remote attacker can
    exploit this to have unspecified impact. (CVE-2015-6836)

  - Multiple flaws exist in the XSLTProcessor class due to
    improper validation of input from the libxslt library. A
    remote attacker can exploit thse flaws to have an
    unspecified impact. (CVE-2015-6837, CVE-2015-6838)

  - A flaw exists in the php_zip_extract_file() function
    in file php_zip.c due to improper sanitization of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this to create arbitrary directories outside
    of the restricted path. (VulnDB 127122)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.5.29");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.5.29 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

version = php["ver"];
source = php["src"];

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

# Check that it is the correct version of PHP
if (version =~ "^5(\.5)?$") audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^5\.5\.") audit(AUDIT_NOT_DETECT, "PHP version 5.5.x", port);

if (version =~ "^5\.5\.([0-9]|1[0-9]|2[0-8])($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.5.29' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
