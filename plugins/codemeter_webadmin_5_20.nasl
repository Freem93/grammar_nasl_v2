#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81439);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/17 21:38:53 $");

  script_cve_id("CVE-2014-8419");
  script_bugtraq_id(71264);
  script_osvdb_id(115024);

  script_name(english:"CodeMeter < 5.20 Local Privilege Escalation Vulnerability");
  script_summary(english:"Checks the CodeMeter WebAdmin version.");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host is affected by a privilege
escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the CodeMeter WebAdmin server
installed on the remote host is prior to 5.20a (5.20.1458.500). It is
affected by insecure read/write permissions for the 'codemeter.exe'
service, which a local attacker can exploit to gain elevated
privileges via a trojan horse file.");
  script_set_attribute(attribute:"solution", value:"Upgrade to CodeMeter 5.20a (5.20.1458.500) or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"see_also", value:"http://www.wibu.com/downloads-user-software.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2014/Nov/124");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wibu:codemeter_runtime");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("codemeter_webadmin_detect.nasl");
  script_require_keys("installed_sw/CodeMeter");
  script_require_ports("Services/www", 22350);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'CodeMeter';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:22350, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port : port,
  exit_if_unknown_ver:TRUE
);

disp_ver = install['display_version'];
ver = install['version'];
dir = install['path'];
install_url = build_url(port:port,qs:dir);

# Version 5.20a was the first 5.20 release
# This version number maps to 5.20.1458.500
fix = '5.20.1458.500';
fix_disp = '5.20a (5.20.1458.500)';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + disp_ver +
      '\n  Fixed version     : ' + fix_disp +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, disp_ver);
