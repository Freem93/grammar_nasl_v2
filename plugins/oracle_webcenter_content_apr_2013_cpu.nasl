#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69478);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/07 21:18:28 $");

  script_cve_id("CVE-2013-1503", "CVE-2013-1522", "CVE-2013-1559");
  script_bugtraq_id(59107, 59110, 59122);
  script_osvdb_id(92384, 92386, 92389);

  script_name(english:"Oracle WebCenter Content (April 2013 CPU)");
  script_summary(english:"Checks the version of Oracle WebCenter Content");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Oracle WebCenter Content installed on the remote host
is potentially affected by multiple vulnerabilities in the Content
Server component."
  );
  # http://www.oracle.com/technetwork/topics/security/cpuapr2013-1899555.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?028971b4");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the appropriate patch according to the April 2013 Oracle
Critical Patch Update advisory."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Oracle WebCenter Content CheckOutAndOpen.dll ActiveX Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_set_attribute(attribute:"vuln_publication_date",value:"2013/04/17");
  script_set_attribute(attribute:"patch_publication_date",value:"2013/04/17");
  script_set_attribute(attribute:"plugin_publication_date",value:"2013/08/20");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

if(main_ver == "11.1.1.6.0")
{
  # Patch 16163273
  # 11gR1-11.1.1.6.0-idcprod1-130212T001239 
  fix_dt = 130212;
  fix_ts = 1239;

  temp = split(sub_ver, sep:"T", keep:FALSE); 
  if(int(temp[0]) < fix_dt ||
    (int(temp[0]) == fix_dt && int(temp[1]) < fix_ts))
  {
    report = '\n  Installed Version : ' + main_ver + ' (' + sub_ver + ')' +
             '\n  Fixed Version     : 11.1.1.6.0 (130212T001239)' +
             '\n  Required Patch    : 16163273\n';
  }
}
else if(main_ver == "10.1.3.5.1")
{
  # Patch 16163273
  # 10.1.3.5.1 (130313)
  fixed_build = 130313;
  build = int(sub_ver);
  if(build < fixed_build)
  {
    report = '\n  Installed Version : ' + main_ver + ' (' + sub_ver + ')' +
             '\n  Fixed Version     : 10.1.3.5.1 (130313)' +
             '\n  Required Patch    : 16163273\n';
  }
}

if(report == '')
  audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, version);

if(report_verbosity > 0)
  security_warning(extra:report, port:port);
else security_warning(port);
