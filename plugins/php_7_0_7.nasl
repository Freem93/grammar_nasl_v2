#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91443);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/06/03 14:00:06 $");

  script_cve_id(
    "CVE-2013-7456",
    "CVE-2016-5093"
  );
  script_osvdb_id(
    139004,
    139005
  );

  script_name(english:"PHP 7.0.x < 7.0.7 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 7.0.x prior to 7.0.7. It is, therefore, affected by multiple
vulnerabilities :

  - An out-of-bounds read error exists in the
    _gdContributionsCalc() function within file
    ext/gd/libgd/gd_interpolation.c. An unauthenticated,
    remote attacker can exploit this to disclose sensitive
    information or crash the process linked against the
    library. (CVE-2013-7456)

  - An out-of-bounds read error exists in the
    get_icu_value_internal() function within file
    ext/intl/locale/locale_methods.c due to improper
    handling of user-supplied input. An unauthenticated,
    remote attacker can exploit this to disclose sensitive
    information or crash the process linked against the
    library. (CVE-2016-5093)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-7.php#7.0.7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.0.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

if (report_paranoia < 2 && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

# Check that it is the correct version of PHP
if (version =~ "^7(\.0)?$")
  audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^7\.0\.") audit(AUDIT_NOT_DETECT, "PHP version 7.0.x", port);

if (version =~ "^7\.0\." && ver_compare(ver:version, fix:"7.0.7", strict:FALSE) < 0){
  security_report_v4(
  port  : port,
  extra :
    '\n  Version source    : ' + source +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 7.0.7' +
    '\n',
  severity:SECURITY_HOLE
  );
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
