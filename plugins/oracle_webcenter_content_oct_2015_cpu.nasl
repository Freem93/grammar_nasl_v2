#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86473);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/28 19:11:32 $");

  script_cve_id("CVE-2015-4867", "CVE-2015-4880");
  script_osvdb_id(129078, 129079);

  script_name(english:"Oracle WebCenter Content Server Multiple Vulnerabilities (October 2015 CPU)");
  script_summary(english:"Checks the version of Oracle WebCenter Content.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple unspecified vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebCenter Content installed on the remote host
is affected by multiple vulnerabilities due to multiple unspecified
flaws in the Content Server component. A remote attacker can exploit
these flaws to impact integrity.");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d408555");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2015 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_webcenter_content_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("installed_sw/Oracle WebCenter Content", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "Oracle WebCenter Content";

if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);

version = install['version'];
dir = install['path'];

install_url = build_url(port: port, qs:dir);

matches = eregmatch(string:version, pattern:"([0-9.]+) \(([0-9.]+)\)");
if (isnull(matches)) audit(AUDIT_VER_FORMAT, version);
main_ver = matches[1];
sub_ver = matches[2];

report = '';

if (main_ver == "10.1.3.5.1")
{
  # Patch 21617488
  # 10.1.3.5.1 (150824)
  fixed_build = 150824;
  build = int(sub_ver);
  if (build < fixed_build)
  {
    report = '\n  Installed version : ' + main_ver + ' (' + sub_ver + ')' +
             '\n  Fixed version     : 10.1.3.5.1 (150824)' +
             '\n  Required patch    : 21617488\n';
  }
}

if (report == '') audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, version);

if (report_verbosity > 0) security_warning(extra:report, port:port);
else security_warning(port);
