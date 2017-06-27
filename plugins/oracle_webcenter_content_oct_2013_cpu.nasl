#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71022);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/03/04 16:15:43 $");

  script_cve_id("CVE-2013-5813");
  script_bugtraq_id(63049);
  script_osvdb_id(98459);

  script_name(english:"Oracle WebCenter Content Server Subcomponent Remote Issue (October 2013 CPU)");
  script_summary(english:"Checks the version of Oracle WebCenter Content");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an unspecified remote security
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebCenter Content installed on the remote host is
potentially affected by an unspecified remote security vulnerability
in the Content Server component.");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac29c174");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2013 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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

if (main_ver == "11.1.1.8.0")
{
  # Patch 17453460
  # 11.1.1.8.0PSU-2013-09-13 15:21:10Z-r110081
  # 11.1.1.8.0 (110081)
  fixed_build = 110081;
  build = int(sub_ver);
  if (build < fixed_build)
  {
    report = '\n  Installed version : ' + main_ver + ' (' + sub_ver + ')' +
             '\n  Fixed version     : 11.1.1.8.0 (110081)' +
             '\n  Required patch    : 17453460\n';
  }
}
else if (main_ver == "11.1.1.7.0")
{
  # Patch 17180477:
  # 11gR1-11.1.1.7.0-idcprod1-130909T054136
  fix_dt = 130909;
  fix_ts = 054136;

  temp = split(sub_ver, sep:"T", keep:FALSE);
  if (
    int(temp[0]) < fix_dt ||
    (int(temp[0]) == fix_dt && int(temp[1]) < fix_ts)
  )
  {
    report = '\n  Installed version : ' + main_ver + ' (' + sub_ver + ')' +
             '\n  Fixed version     : 11.1.1.7.0 (130909T054136)' +
             '\n  Required patch    : 17180477\n';
  }
}
else if (main_ver == "11.1.1.6.0")
{
  # Patch 17046964:
  # 11gR1-11.1.1.6.0-idcprod1-130806T205208
  fix_dt = 130806;
  fix_ts = 205208;

  temp = split(sub_ver, sep:"T", keep:FALSE);
  if (
    int(temp[0]) < fix_dt ||
    (int(temp[0]) == fix_dt && int(temp[1]) < fix_ts)
  )
  {
    report = '\n  Installed version : ' + main_ver + ' (' + sub_ver + ')' +
             '\n  Fixed version     : 11.1.1.6.0 (130806T205208)' +
             '\n  Required patch    : 17046964\n';
  }
}
else if (main_ver == "10.1.3.5.1")
{
  # Patch 17289573
  # 10.1.3.5.1 (130829)
  fixed_build = 130829;
  build = int(sub_ver);
  if (build < fixed_build)
  {
    report = '\n  Installed version : ' + main_ver + ' (' + sub_ver + ')' +
             '\n  Fixed version     : 10.1.3.5.1 (130829)' +
             '\n  Required patch    : 17289573\n';
  }
}

if (report == '') audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, version);

if (report_verbosity > 0) security_warning(extra:report, port:port);
else security_warning(port);
