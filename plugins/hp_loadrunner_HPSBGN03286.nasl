#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83815);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id("CVE-2015-2110");
  script_bugtraq_id(74737);
  script_osvdb_id(122344);
  script_xref(name:"HP", value:"HPSBGN03286");
  script_xref(name:"HP", value:"SSRT101319");
  script_xref(name:"HP", value:"emr_na-c04594015");

  script_name(english:"HP LoadRunner 11.52 Buffer Overflow RCE");
  script_summary(english:"Checks the version of an HP LoadRunner library file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP LoadRunner installed on the remote host is 11.52
without the proper patch to 'two_way_comm.dll'. It is, therefore,
affected by a buffer overflow flaw that can allow an unauthenticated,
remote attacker to execute arbitrary code in the context of the HP
LoadRunner Agent process.");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04594015
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f51e439");
  script_set_attribute(attribute:"solution", value:"Apply the patch provided by HP.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:loadrunner");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_loadrunner_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/HP LoadRunner");
  script_require_ports(139, 445);

  exit(0);
}

include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('misc_func.inc');
include("install_func.inc");

app_name = "HP LoadRunner";

# Only 1 install of the server is possible.
install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];
verui   = install['display_version'];
report  = NULL;
dllfix  = "11.52.65535.0";
# Located in two places, both must be updated
files   = make_list("bin\two_way_comm.dll","launch_service\bin\two_way_comm.dll");

if(version !~ "^11\.52\.")
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

foreach file (files)
{
  dllpath = path + file;
  res = hotfix_get_fversion(path:dllpath);
  hotfix_handle_error(
    error_code   : res['error'],
    file         : dllpath,
    appname      : app_name,
    exit_on_fail : TRUE
  );

  dllver = join(sep:'.', res['value']);

  if(ver_compare(ver:dllver,fix:dllfix) < 0)
  {
    report +=
        '\n  Path                  : ' + dllpath +
        '\n  Installed DLL version : ' + dllver  +
        '\n  Fixed DLL version     : ' + dllfix  +
        '\n';
  }
}
hotfix_check_fversion_end();

# Both DLLs patched
if(isnull(report))
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

port   = kb_smb_transport();
report =
    '\n  Product Root path     : ' + path +
    '\n  Product version       : ' + version +
    '\n' + report;

if(report_verbosity > 0) 
  security_hole(extra:report, port:port);
else
  security_hole(port);
