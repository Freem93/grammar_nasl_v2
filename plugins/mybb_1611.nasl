#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72686);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/06/20 20:49:18 $");

  script_bugtraq_id(62933);
  script_osvdb_id(98315, 98316, 98317, 98318, 98319);

  script_name(english:"MyBB < 1.6.11 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MyBB.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the MyBB install running on the
remote web server is affected by multiple vulnerabilities :

  - A flaw exists in which accounts without login keys can
    be hijacked. (VulnDB 98315)

  - An information disclosure vulnerability exists due to
    improper implementation of UTF8. A remote attacker can
    exploit this to bypass authorization checks on viewing
    private messages. (VulnDB 98316)

  - An information disclosure vulnerability exists due to
    log files exposing database backup information.
    (VulnDB 98317)

  - An information disclosure vulnerability exists due to
    anonymous statistics not always being set as anonymous.
    (VulnDB 98318)

  - An unspecified flaw exists in the generate_post_check()
    that allows an attacker to have an unspecified impact.
    (VulnDB 98319)

Note that Nessus has not tested for these issues but has instead
relied on the application's self-reported version number.");
  # http://blog.mybb.com/2013/10/08/mybb-1-6-11-released-security-maintenance-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1bc0e0c7");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.6.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mybb:mybb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("mybb_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/MyBB", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "MyBB";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

version = install['version'];
install_url = build_url(port:port, qs:install['path']);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = "1.6.11";
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
