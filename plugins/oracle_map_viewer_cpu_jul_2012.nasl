#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78087);
  script_version("$Revision $");
  script_cvs_date("$Date: 2014/10/08 15:18:26 $");

  script_cve_id("CVE-2012-1736", "CVE-2012-1749", "CVE-2012-3115");
  script_bugtraq_id(54514, 54520, 54516);
  script_osvdb_id(83913, 83915, 83917);

  script_name(english:"Oracle MapViewer Multiple Vulnerabilities (July 2012 CPU)");
  script_summary(english:"Checks the version of Oracle MapViewer.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Oracle
Fusion Middleware MapViewer installed on the remote host is affected
by the following vulnerabilities :

  - There is an unspecified flaw related to the Oracle Maps
    subcomponent that allows a remote attacker to gain
    access to potentially sensitive information.
    (CVE-2012-1736, CVE-2012-1749)

  - There is an unspecified flaw related to the Install
    subcomponent that allows a remote attacker to have an
    impact on integrity. (CVE-2012-3115)");
  # http://www.oracle.com/technetwork/topics/security/cpujul2012-392727.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd39edea");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2012 Oracle Critical
Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:oracle:mapviewer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("oracle_map_viewer_detect.nbin");
  script_require_keys("installed_sw/Oracle MapViewer");
  script_require_ports("Services/www", 8888, 8080, 80, 443);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = "Oracle MapViewer";
get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:8888);

install = get_single_install(
  app_name : appname,
  port     : port,
  exit_if_unknown_ver : TRUE
);

path     = install['path'];
version  = install['version'];
disp_ver = install['display_version'];
url      = build_url(port:port, qs:path);

if (
  ver_compare(ver:version, fix:10.1.3.1) == 0 ||
  ver_compare(ver:version, fix:11.1.1.5) == 0 ||
  ver_compare(ver:version, fix:11.1.1.6) == 0
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL                : ' + url +
      '\n  Display version    : ' + disp_ver +
      '\n  Version            : ' + version +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);
