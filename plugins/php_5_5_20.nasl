#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80331);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/20 14:21:44 $");

  script_cve_id("CVE-2014-8142");
  script_bugtraq_id(71791);
  script_osvdb_id(116020);

  script_name(english:"PHP 5.5.x < 5.5.20 'process_nested_data' RCE");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP 5.5.x installed on the
remote host is prior to 5.5.20. It is, therefore, affected by a
use-after-free error in the 'process_nested_data' function within
'ext/standard/var_unserializer.re' due to improper handling of
duplicate keys within the serialized properties of an object. A remote
attacker, using a specially crafted call to the 'unserialize' method,
can exploit this flaw to execute arbitrary code on the system.

Note that Nessus has not attempted to exploit this issue but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.5.20");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=68594");
  # https://bugzilla.redhat.com/show_bug.cgi?id=1175718
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?88c4ed71");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 5.5.20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/02");

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

if (version =~ "^5\.5\.([0-9]|1[0-9])($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : '+source +
      '\n  Installed version : '+version +
      '\n  Fixed version     : 5.5.20' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);