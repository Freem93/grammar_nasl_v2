#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69401);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/20 14:21:44 $");

  script_cve_id("CVE-2013-4113", "CVE-2013-4248");
  script_bugtraq_id(61128, 61776);
  script_osvdb_id(95152, 96298);

  script_name(english:"PHP 5.4.x < 5.4.18 Multiple Vulnerabilities");
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
"According to its banner, the version of PHP 5.4.x installed on the
remote host is a version prior to 5.4.18.  It is, therefore,
potentially affected by the following vulnerabilities :

  - A heap corruption error exists in numerous functions
    in the file 'ext/xml/xml.c'. (CVE-2013-4113 / 
    Bug #65236)

  - An error exists related to certificate validation, the
    'subjectAltName' field and certificates containing NULL
    bytes. This error can allow spoofing attacks.
    (CVE-2013-4248)

Note that this plugin does not attempt to exploit these 
vulnerabilities, but instead relies only on PHP's self-reported
version number."
  );
  script_set_attribute(attribute:"see_also", value:"http://bugs.php.net/65236");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.4.18");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.4.19 or later.

Note the 5.4.18 release contains an uninitialized memory read bug and
a compile error that prevent proper operation.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

if (report_paranoia < 2 && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

# Check that it is the correct version of PHP
if (version =~ "^5(\.4)?$") exit(1, "The banner from the PHP install associated with port "+port+" - "+version+" - is not granular enough to make a determination.");
if (version !~ "^5\.4\.") audit(AUDIT_NOT_DETECT, "PHP version 5.4.x", port);

if (version =~ "^5\.4\.([0-9]|1[0-7])($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : '+source +
      '\n  Installed version : '+version+
      '\n  Fixed version     : 5.4.18\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
