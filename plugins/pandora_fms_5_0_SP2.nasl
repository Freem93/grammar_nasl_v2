#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81148);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/20 14:21:44 $");

  #script_cve_id();
  script_bugtraq_id(71325);
  script_osvdb_id(115078);
  script_xref(name:"EDB-ID", value:"35380");

  script_name(english:"Pandora FMS <= 5.0 SP2 SQLi");
  script_summary(english:"Checks the version of Pandora FMS.");

  script_set_attribute(attribute:"synopsis", value:
"A web console on the remote host is affected by a SQL injection
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Pandora FMS console hosted on the remote web server is version 5.0
SP2 or prior. It is, therefore, affected by a SQL injection
vulnerability via the 'user' parameter of the mobile login interface,
which a remote attacker can exploit to inject SQL queries into the
back-end database, resulting in disclosure or manipulation of data.");
  script_set_attribute(attribute:"see_also", value:"http://blog.pandorafms.org/?p=2041");
  script_set_attribute(attribute:"solution", value:"Apply the vendor supplied security fix or upgrade to version 5.0 SP3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Pandora FMS 5.0 SP2 SQL Injection");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:artica:pandora_fms");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("pandora_fms_console_detect.nasl");
  script_require_keys("installed_sw/Pandora FMS");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'Pandora FMS';
get_install_count(app_name:app, exit_if_zero:TRUE);

port    = get_http_port(default:80, php:TRUE);
install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
dir     = install["path"];
version = install["version"];

# Versions 5.0 SP2 and below are vulnerable
if (
  version =~ "^v?[0-4]\." ||
  version =~ "^v?5\.0((SP|RC)[12])?$"
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : v5.0SP3' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:install['dir'], port:port), version);
