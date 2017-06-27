#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81515);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/26 14:38:27 $");

  script_cve_id("CVE-2014-2664");
  script_bugtraq_id(66506);
  script_osvdb_id(105070);

  script_name(english:"X2Engine < 4.0 ProfileController.php Unrestricted File Upload Vulnerability");
  script_summary(english:"Checks the version of X2Engine.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
file upload vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the X2Engine application installed on
the remote web server is prior to version 4.0. It is, therefore,
potentially affected by a file upload vulnerability in the
'/protected/controllers/ProfileController.php' script. An attacker can
exploit this issue to upload arbitrary code to the remote host to be
executed within the context of the web server user.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://karmainsecurity.com/KIS-2014-04");
  script_set_attribute(attribute:"see_also", value:"http://x2community.com/topic/1535-x2engine-40/");
  script_set_attribute(attribute:"see_also", value:"https://github.com/X2Engine/X2Engine/blob/master/CHANGELOG.md");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:x2engine:x2crm");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("x2engine_detect.nbin");
  script_require_keys("www/PHP", "installed_sw/X2Engine", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "X2Engine";
fix = "4.0";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
install_url = build_url(port:port, qs:dir + "/login");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] < 4)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : ' +fix+
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
