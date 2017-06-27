#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76873);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/06 17:22:03 $");

  script_cve_id("CVE-2014-4663");
  script_bugtraq_id(68180);
  script_osvdb_id(108398);
  script_xref(name:"EDB-ID", value:"33851");

  script_name(english:"TimThumb 'timthumb.php' < 2.8.14 WebShot 'src' Parameter Remote Command Execution");
  script_summary(english:"Checks the plugin / script version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a remote
command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The TimThumb 'timthumb.php' script installed on the remote host is
prior to version 2.8.14. It is, therefore, affected by a remote
command execution vulnerability due to a failure to properly sanitize
user-supplied input to the 'src' parameter. A remote, unauthenticated
attacker can leverage this issue to execute arbitrary commands on the
remote host. Note that the script is only affected when the 'WebShot'
feature is enabled.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2014/Jun/117");
  script_set_attribute(attribute:"see_also", value:"https://code.google.com/p/timthumb/source/detail?r=219");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.8.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:binarymoon:timthumb");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:timthumb:timthumb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl", "wordpress_timthumb_detect.nbin");
  script_require_keys("www/PHP", "installed_sw/WordPress", "installed_sw/TimThumb", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "WordPress";
plugin = "TimThumb";
get_install_count(app_name:plugin, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : plugin,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
install_url = build_url(port:port, qs:dir);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] < 2) ||
  (ver[0] == 2 && ver[1] < 8) ||
  (ver[0] == 2 && ver[1] == 8 && ver[2] < 14)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 2.8.14\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin, version);
