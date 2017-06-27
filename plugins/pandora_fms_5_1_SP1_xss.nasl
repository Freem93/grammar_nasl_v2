#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81166);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/05 16:58:07 $");

  script_cve_id("CVE-2014-8629");
  script_bugtraq_id(71277);
  script_osvdb_id(114643);

  script_name(english:"Pandora FMS <= 5.1 SP1 XSS");
  script_summary(english:"Checks the version of Pandora FMS.");

  script_set_attribute(attribute:"synopsis", value:
"A web console on the remote host is affected by an XSS vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Pandora FMS console hosted on the remote web server is version
5.1 SP1 or prior. It is, therefore, affected by a cross-site scripting
vulnerability due to a flaw in 'index.php' where the 'refr' parameter
is not properly validated before being returned to users. This can
allow a remote attacker to execute arbitrary script code in a user's
browser session.

Note that the vendor supplied fix for this vulnerability does not
update the version number reported by the application. If this fix has
already been applied, disregard this finding.");
  script_set_attribute(attribute:"see_also", value:"http://blog.pandorafms.org/?p=3271");
  script_set_attribute(attribute:"solution", value:"Apply the vendor supplied fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:artica:pandora_fms");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("pandora_fms_console_detect.nasl");
  script_require_keys("installed_sw/Pandora FMS", "Settings/ParanoidReport");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = 'Pandora FMS';
get_install_count(app_name:app, exit_if_zero:TRUE);

port    = get_http_port(default:80, php:TRUE);
install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
dir     = install["path"];
version = install["version"];

# Versions 5.1 SP1 and below are vulnerable
if (
  version =~ "^v?[0-4]\." ||
  version =~ "^v?5\.0([^0-9]|$)" ||
  version =~ "^v?5\.1(SP1(RC[1-3])?|BETA1|RC[12])?$"
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : Apply vendor supplied patch.' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:install['dir'], port:port), version);
