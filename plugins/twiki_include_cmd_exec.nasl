#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20068);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/04/21 13:25:43 $");

  script_cve_id("CVE-2005-3056");
  script_bugtraq_id(14960);
  script_osvdb_id(19716);

  script_name(english:"TWiki %INCLUDE Parameter Arbitrary Command Injection");
  script_summary(english:"Checks for INCLUDE function command execution vulnerability in TWiki.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a CGI script that is affected by an
arbitrary shell command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the installed version of TWiki allows an
attacker to manipulate input to the 'rev' parameter in order to
execute arbitrary shell commands on the remote host subject to the
privileges of the web server user id.");
  # http://twiki.org/cgi-bin/view/Codev/SecurityAlertExecuteCommandsWithInclude
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b15c2dd7");
  script_set_attribute(attribute:"solution", value:"Apply the appropriate hotfix listed in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:twiki:twiki");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("twiki_detect.nasl");
  script_require_keys("installed_sw/TWiki", "Settings/ParanoidReport");
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
ver = install['version'];
install_url = build_url(port:port, qs:dir);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (ver =~ "^(0[123] Sep 2004|01 Feb 2003)$")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : 04 Sep 2004 or apply the appropriate hotfix' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, ver);
