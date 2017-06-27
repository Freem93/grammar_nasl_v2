#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64876);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/04/21 13:25:43 $");

  script_cve_id("CVE-2013-1751");
  script_bugtraq_id(58024);
  script_osvdb_id(90345);

  script_name(english:"TWiki < 5.1.4 MAKETEXT Variable Tilde Character Command Injection");
  script_summary(english:"Checks version of TWiki.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a CGI application that is affected by a
command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the instance of TWiki running on
the remote host is affected by a command injection vulnerability. The
'%MAKETEXT{}%' variable fails to properly sanitize user-supplied
input. A remote attacker can exploit this issue to execute arbitrary
shell commands on the remote host subject to the privileges of the web
server user. 

Note that only TWiki installs with localization enabled are affected.

Nessus has not tested for this issue but has instead relied only on
the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://twiki.org/cgi-bin/view/Codev/SecurityAlert-CVE-2013-1751");
  script_set_attribute(attribute:"solution", value:
"Upgrade to TWiki version 5.1.4 or later. Alternatively, apply the
hotfix referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:twiki:twiki");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("twiki_detect.nasl");
  script_require_keys("Settings/ParanoidReport", "installed_sw/TWiki");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "TWiki";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
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

# Versions 4.0.x - 5.1.3 are affected
if (
  # 4.X
  (ver[0] == 4) ||
  # 5.x < 5.1.4
  (ver[0] == 5 && ver[1] < 1) ||
  (ver[0] == 5 && ver[1] == 1 && ver[2] < 4)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.1.4' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
