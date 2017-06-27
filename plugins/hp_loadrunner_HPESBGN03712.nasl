#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97888);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/03/24 14:10:48 $");

  script_cve_id("CVE-2017-5789");
  script_bugtraq_id(96774);
  script_osvdb_id(153267);
  script_xref(name:"HP", value:"HPESBGN03712");
  script_xref(name:"IAVA", value:"2017-A-0055");
  script_xref(name:"HP", value:"emr_na-hpesbgn03712en_us");
  script_xref(name:"TRA", value:"TRA-2011-05");
  script_xref(name:"ZDI", value:"ZDI-17-160");

  script_name(english:"HPE LoadRunner < 12.53 Patch 4 libxdrutil.dll mxdr_string() RCE");
  script_summary(english:"Checks the version of HP LoadRunner.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP LoadRunner installed on the remote Windows host is
prior to 12.53 patch 4. It is, therefore, affected by a remote code
execution vulnerability due to a heap-based buffer overflow condition
in the mxdr_string() function in libxdrutil.dll. An unauthenticated,
remote attacker can exploit this to execute arbitrary code.");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbgn03712en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1935cc18");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2017-13");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-160/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP LoadRunner version 12.53 patch 4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:loadrunner");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("hp_loadrunner_installed.nasl");
  script_require_keys("installed_sw/HP LoadRunner");
  script_require_ports(139, 445);

  exit(0);
}

include('audit.inc');
include('misc_func.inc');
include("install_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

app_name = "HP LoadRunner";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
path = install['path'];
verui = install['display_version'];
vuln = FALSE;
note = '';

fix = '12.53'; # Patch 4

# below 12.53
if (ver_compare(ver:verui, fix:fix, strict:FALSE) < 0)
{
  vuln = TRUE;
}
else if (ver_compare(ver:verui, fix:fix, strict:FALSE) == 0)
{
  file = "LrwNetSocket.dll";
  dll_path = path + "bin\" + file;
  res = hotfix_get_fversion(path:dll_path);
  err_res = hotfix_handle_error(
    error_code   : res['error'],
    file         : dll_path,
    appname      : app_name,
    exit_on_fail : FALSE
  );
  hotfix_check_fversion_end();
  dll_ver = join(sep:'.', res['value']);

  if (empty_or_null(dll_ver))
    audit(AUDIT_VER_FAIL, file + " under " + path + "bin\");

  fixed_dll_ver = '12.53.1982.0';
  if (ver_compare(ver:dll_ver, fix:fixed_dll_ver, strict:FALSE) == -1)
  {
    vuln = TRUE;
  }
}

if (!vuln)
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, verui, path);

port = kb_smb_transport();
if (!port) port = 445;

order = make_list("Path", "Installed version", "Fixed version");
items = make_array(
  order[0], path,
  order[1], verui,
  order[2], fix + " Patch 4 or later"
);
report = report_items_str(report_items:items, ordered_fields:order);

security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
