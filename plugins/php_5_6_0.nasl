#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78556);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/10/17 23:47:14 $");

  script_cve_id("CVE-2014-0236");

  script_name(english:"PHP 5.6.0 Development Releases CDF File NULL Pointer Dereference DoS");
  script_summary(english:"Checks version of PHP");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP installed on the remote
host is a development version of 5.6.0. It is, therefore, affected by
a NULL pointer dereference error in the 'libmagic' library of the
'fileinfo' extension when processing malformed CDF files. By uploading
a specially crafted CDF file to the host, a remote attacker can cause
a denial of service.

Note that Nessus has not attempted to exploit this issue but has
instead relied only on application's self-reported version number.");
  # http://git.php.net/?p=php-src.git;a=commitdiff;h=f3f22ff5c697aef854ffc1918bce708b37481b0f
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab45889c");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=67329");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.6.0");
  script_set_attribute(attribute:"solution", value:"Upgrade to the stable version of PHP 5.6.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/17");

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
php = get_php_from_kb(port: port, exit_on_fail: TRUE);

version = php["ver"];
source  = php["src"];

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

# Check that it is the correct version of PHP
if (version =~ "^5(\.6)?$") audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^5\.6\.0(alpha|beta|RC|rc)")
  audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);

if (report_verbosity > 0)
{
  report =
    '\n  Version source    : '+source +
    '\n  Installed version : '+version+
    '\n  Fixed version     : 5.6.0\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
exit(0);
