#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72511);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/05/29 04:24:09 $");

  script_cve_id(
    "CVE-2013-7226",
    "CVE-2013-7327",
    "CVE-2013-7328",
    "CVE-2014-2020"
  );
  script_bugtraq_id(
    65533, 
    65656,
    65668,
    65676
  );
  script_osvdb_id(103310, 103478, 103479, 103480);

  script_name(english:"PHP 5.5.x < 5.5.9 GD Extension Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server uses a version of PHP that is potentially
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of PHP 5.5.x installed on the
remote host is a version prior to 5.5.9.  It is, therefore, potentially
affected by the following vulnerabilities related to the GD
extension :

  - A heap-based buffer overflow error exists related to
    the functions 'gdImageCrop' and 'imagecrop' that could
    allow denial of service attacks and possibly arbitrary
    code execution. (CVE-2013-7226) 

  - An error exists in the function 'gdImageCrop' related
    to return value checking that could lead to use of
    NULL pointers and denial of service attacks.
    (CVE-2013-7327)

  - Multiple integer signedness errors exist in the
    function 'gdImageCrop' that could allow denial of
    service attacks and information disclosure.
    (CVE-2013-7328)

  - A data type checking error exists that could allow
    information disclosure. (CVE-2014-2020)

Note that this plugin does not attempt to exploit these issues, but
instead relies only on PHP's self-reported version number."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.5.9");
  # https://github.com/php/php-src/commit/2938329ce19cb8c4197dec146c3ec887c6f61d01
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6647cc34");
  # https://github.com/php/php-src/commit/8f4a5373bb71590352fd934028d6dde5bc18530b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3051053");
  script_set_attribute(attribute:"see_also", value:"https://hackerone.com/reports/1356");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 5.5.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
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

if (version =~ "^5\.5\.[0-8]($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : '+source +
      '\n  Installed version : '+version+
      '\n  Fixed version     : 5.5.9\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
