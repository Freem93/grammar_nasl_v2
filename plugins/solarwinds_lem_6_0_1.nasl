#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78915);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/11/07 20:52:12 $");

  script_cve_id("CVE-2014-5504");
  script_bugtraq_id(69559);
  script_osvdb_id(110872);

  script_name(english:"SolarWinds Log and Event Manager < 6.0.1 HyperSQL Remote Code Execution");
  script_summary(english:"Checks the version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
SolarWinds Log and Event Manager on the remote host is a version prior
to 6.0.1. It is, therefore, affected by a flaw in HyperSQL that allows
a remote, unauthenticated user to execute arbitrary code under the
context of the database on the remote host.

Note that some instances of version 6.0.0 may not be affected. Contact
the vendor for more information.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # http://www.zerodayinitiative.com/advisories/ZDI-14-303/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ceda8a0");
  # http://www.solarwinds.com/documentation/lem/docs/releasenotes/releasenotes.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b93cc4f9");
  script_set_attribute(attribute:"solution", value:"Upgrade to SolarWinds Log and Event Manager version 6.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/07");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:log_and_event_manager");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

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

# Only report on version 6.0.0 if running with Paranoid reporting
if (version == "6.0.0" && report_paranoia < 2)
  exit(0, "The install of " + app + " is version " + version_ui + " and may be affected. Refer to the vendor for more information.");

fix = "6.0.1";
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
