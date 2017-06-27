#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77221);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/08/15 20:33:00 $");

  script_cve_id("CVE-2012-0543");
  script_bugtraq_id(53083);
  script_osvdb_id(81379);

  script_name(english:"Oracle Business Intelligence Publisher April 2012 Critical Patch Update");
  script_summary(english:"Checks remote version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Business Intelligence Publisher install is missing
the April 2012 Critical Patch Update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Oracle
Business Intelligence Publisher install is missing the April 2012
Critical Patch Update. It is, therefore, affected by an unspecified
vulnerability related to Administration.");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2012-366314.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9865fa8a");
  script_set_attribute(attribute:"solution", value:"Apply the Oracle April 2012 critical patch update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence_publisher");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("oracle_bi_publisher_detect.nasl");
  script_require_keys("installed_sw/Oracle BI Publisher");
  script_require_ports("Services/www", 9704, 8888, 7001);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = 'Oracle BI Publisher';
get_install_count(app_name:app_name, exit_if_zero:TRUE);

port = get_http_port(default:9704);
install = get_single_install(app_name:app_name, port:port, exit_if_unknown_ver:TRUE);

dir = install['path'];
install_url = build_url(port:port, qs:dir+"/login.jsp");

version = install['version'];
build = install['Build'];

report = '';
if (version =~ '^10\\.1\\.3\\.4\\.1([^0-9]|$)')
{
  report =
    '\n  Installed version : ' + version + ' build ' + build +
    '\n  Fixed version     : 10.1.3.4.2 build 1305' +
    '\n  Required patch    : 13647402\n';
}
if (version =~ '^10\\.1\\.3\\.4\\.2([^0-9]|$)')
{
  if (build !~ "^[0-9.]+$") exit(0, "Unexpected build string format for the Oracle BI Publisher install at "+install_url+".");
  if (ver_compare(ver:build, fix:'1305', strict:FALSE) == -1)
  {
    report =
      '\n  Installed version : ' + version + ' build ' + build +
      '\n  Fixed version     : 10.1.3.4.2 build 1305' +
      '\n  Required patch    : 1364702\n';
  }
}

if (report)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      report;
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url, version + ' build ' + build);
