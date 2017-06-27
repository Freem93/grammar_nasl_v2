#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51439);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/16 14:22:05 $");

  script_cve_id("CVE-2010-4645");
  script_bugtraq_id(45668);
  script_osvdb_id(70370);

  script_name(english:"PHP 5.2 < 5.2.17 / 5.3 < 5.3.5 String To Double Conversion DoS");
  script_summary(english:"Checks version of PHP");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server uses a version of PHP that is affected by
a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of PHP 5.x installed on the
remote host is older than 5.2.17 or 5.3.5. 

Such versions may experience a crash while performing string to double
conversion for certain numeric values.  Only x86 32-bit PHP processes
are known to be affected by this issue regardless of whether the
system running PHP is 32-bit or 64-bit."
  );

  script_set_attribute(attribute:"see_also", value:"http://bugs.php.net/bug.php?id=53632");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/distributions/test_bug53632.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/5_2_17.php");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/5_3_5.php");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP 5.2.17/5.3.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

if (
  (version =~ "^5\.2\.([0-9]|1[0-6])($|[^0-9])") ||
  (version =~ "^5\.3\.[0-4]($|[^0-9])")
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.2.17/5.3.5\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
