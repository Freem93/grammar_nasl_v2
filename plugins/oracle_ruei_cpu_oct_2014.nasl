#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81001);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/10 20:49:25 $");

  script_cve_id("CVE-2014-6557");
  script_bugtraq_id(70512);
  script_osvdb_id(113303);

  script_name(english:"Oracle Real User Experience Insight October 2014 CPU");
  script_summary(english:"Checks the version of Oracle RUEI.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by an unspecified vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Real User Experience Insight 12.1.0.6 is missing
the October 2014 Critical Patch Update. It is, therefore, affected by
an unspecified vulnerability that can be exploited by an
authenticated, remote attacker to impact confidentiality and
integrity.");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6dcc7b47");
  script_set_attribute(attribute:"solution", value:"Apply the October 2014 CPU.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager_grid_control");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_ruei_detect.nbin");
  script_require_keys("installed_sw/Oracle Real User Experience Insight");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("http.inc");
include("install_func.inc");

appname = 'Oracle Real User Experience Insight';
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:443);

install = get_single_install(app_name:appname, port:port);
url = build_url(port:port, qs:install['path']);
version = install['version'];
if (version =~ '^12\\.1\\.0\\.6$') audit(AUDIT_VER_NOT_GRANULAR, appname, port, version);

if (version =~ '^12\\.1\\.0\\.6\\.' && ver_compare(ver:version, fix:'12.1.0.6.1', strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL: ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 12.1.0.6.1 / 12.1.0.6.2\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);
