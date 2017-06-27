#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96270);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/01/05 14:33:07 $");

  script_cve_id("CVE-2016-8512");
  script_osvdb_id(149128);
  script_xref(name:"HP", value:"emr_na-c05354136");
  script_xref(name:"HP", value:"HPSBGN03679");

  script_name(english:"HP LoadRunner MMS Protocol Buffer Overflow RCE");
  script_summary(english:"Checks if MMSEngine.dll or MM1Client.dll are present.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP LoadRunner installed on the remote Windows host is
affected by an unspecified buffer overflow condition in the MMS
protocol due to improper validation of user-supplied input. An
unauthenticated, remote attacker can exploit this to cause a denial of
service condition or the execution of arbitrary code.");
  # http://h20565.www2.hpe.com/hpsc/doc/public/display?docLocale=en_US&docId=emr_na-c05354136
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a50633cf");
  script_set_attribute(attribute:"solution", value:
"Remove the files MMSEngine.dll and MM1Client.dll as directed by HP.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:loadrunner");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("hp_loadrunner_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/HP LoadRunner");
  script_require_ports(139, 445);

  exit(0);
}

include('audit.inc');
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");

app_name = "HP LoadRunner";

# Only 1 install of the server is possible.
install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];
verui   = install['display_version'];
report  = NULL;

files   = make_list("bin\MMSEngine.dll", "bin\MM1Client.dll");

# MMS protocol deprecated in 12.53, so prevent from flagging on this and above
if (ver_compare(ver:version,fix:"12.53", strict:FALSE) >= 0)
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

foreach file (files)
{
  dllpath = path + file;

  res = hotfix_file_exists(path:dllpath);

  if(isnull(res)) audit(AUDIT_FN_FAIL, 'hotfix_file_exists');
  else if (res)
  {
    file = ereg_replace(pattern:"^bin\\", string:file, replace:"");
    report +=
        '\n  Path              : ' + dllpath +
        '\n  File              : ' + file  +
        '\n';
  }
}
hotfix_check_fversion_end();

# Both DLLs removed
if(isnull(report))
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

port = get_kb_item('SMB/transport');
if (!port) port = 445;

report =
    '\n  Product Root path : ' + path +
    '\n  Product version   : ' + version +
    '\n' + report;

security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
exit(0);
