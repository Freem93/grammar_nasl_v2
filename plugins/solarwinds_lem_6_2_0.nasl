#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86425);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/04/29 19:33:20 $");

  script_cve_id("CVE-2015-7839", "CVE-2015-7840");
  script_bugtraq_id(77016, 77118);
  script_osvdb_id(128555, 128951);
  script_xref(name:"IAVA", value:"2015-A-0254");

  script_name(english:"SolarWinds Log and Event Manager < 6.2.0 Multiple Remote Command Execution Vulnerabilities");
  script_summary(english:"Checks the LEM version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application is affected by multiple remote command
execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the SolarWinds Log and
Event Manager installed on the remote host is prior to version 6.2.0.
It is, therefore, affected by multiple vulnerabilities :

  - A flaw exists in the messagebroker/nonsecurestreamingamf
    service when using the traceroute functionality. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary commands
    on managed hosts using the LEM agent connected to the
    Log and Event Manager. (CVE-2015-7839)

  - A flaw exists in the command line management console
    (CMC) related to the Ping feature. A remote attacker can
    exploit this, by using specially crafted text in
    response to the prompts, to open a bash shell, thus
    allowing the execution of arbitrary commands.
    (CVE-2015-7840)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www.zerodayinitiative.com/advisories/ZDI-15-461/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?486e0b2b");
  # http://www.solarwinds.com/documentation/lem/docs/releasenotes/releasenotes.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b93cc4f9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SolarWinds Log and Event Manager version 6.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/19");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:log_and_event_manager");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("solarwinds_lem_detect.nbin");
  script_require_keys("installed_sw/SolarWinds Log and Event Manager");
  script_require_ports("Services/www", 8080, 8443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:8080);

app  = "SolarWinds Log and Event Manager";
install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

dir        = install['path'];
version    = install['version'];
version_ui = install['display_version'];

install_url = build_url(port:port, qs:dir);

fix = "6.2.0";
if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  URL               : ' + install_url +
    '\n  Installed version : ' + version_ui +
    '\n  Fixed version     : ' + fix +
    '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version_ui);
