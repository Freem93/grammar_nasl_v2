#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87211);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/06/13 13:30:10 $");

  script_cve_id("CVE-2015-6857");
  script_bugtraq_id(77946);
  script_osvdb_id(130684);
  script_xref(name:"HP", value:"HPSBGN03523");
  script_xref(name:"HP", value:"emr_na-c04900820");

  script_name(english:"HP LoadRunner 11.52 / 12.00 / 12.01 / 12.02 / 12.50 Virtual Table Server RCE");
  script_summary(english:"Checks the version of HP LoadRunner.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP LoadRunner installed on the remote host is 11.52,
12.00, 12.01, 12.02, or 12.50. It is, therefore, affected by a remote
code execution vulnerability in the Virtual Table Server (VTS). An
unauthenticated, remote attacker can exploit this, via a malicious
connection string or SQL command, to execute arbitrary code.");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04900820
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?917f4e68");
  # https://packetstormsecurity.com/files/134546/HP-Security-Bulletin-HPSBGN03523-1.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6cf43203");
  # https://softwaresupport.hp.com/group/softwaresupport/search-result/-/facetsearch/document/KM01936061
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?363abef6");
  script_set_attribute(attribute:"solution", value:
"Delete the web\admin\adoUtility.js file.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/05");

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

app_name = "HP LoadRunner - VTS" ;
report  = NULL ;
display_names = get_kb_list_or_exit("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName") ;
present = NULL ;
if (display_names)
  {
    foreach item (keys(display_names))
      {
        if (app_name >< display_names[item])
          {
            install_path_key = (item - 'DisplayName') + 'InstallLocation';
            disp_ver_key = (item - 'DisplayName') + 'DisplayVersion';
            hplr_ins_path = get_kb_item(install_path_key);
            version = get_kb_item(disp_ver_key);
            present = TRUE ;
          }
      }
    if (present == NULL)
      {
        audit(AUDIT_NOT_INST, "HP LoadRunner - VTS");
      }
  }
# 11.52 / 12.00 12.01 12.02 12.50
if (version =~ "^11\.52($|[^0-9])" ||
    version =~ "^12\.0[0-2]($|[^0-9])" ||
    version =~ "^12\.50($|[^0-9])" )
  {
    # 11.52 location
    adoFile = hplr_ins_path + "\web\engine\admin\adoUtility.js";
    res = hotfix_file_exists(path:adoFile);
    if(isnull(res)) audit(AUDIT_FN_FAIL, 'hotfix_file_exists');
  
    # Try another location 
    if(res == FALSE)
    {
      adoFile = hplr_ins_path + "\web\admin\adoUtility.js";
      res = hotfix_file_exists(path:adoFile);
      if(isnull(res)) audit(AUDIT_FN_FAIL, 'hotfix_file_exists');
    }
    if(res == TRUE){
      adoFile = str_replace(string:adoFile, find:"\\", replace:"\");
      report =
        '\n  Vulnerable file       : ' + adoFile +
        '\n  Fix                   : Delete the adoUtility.js file. \n';
    } else {
      audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, hplr_ins_path);
    }
    hotfix_check_fversion_end();
  } else {
    audit(AUDIT_NOT_INST, app_name + " 11.52.x / 12.00.x / 12.01.x / 12.02.x / 12.50.x");
}

if (isnull(report)) audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, hplr_ins_path);

port = kb_smb_transport();

if (report_verbosity > 0) security_hole(extra:report, port:port);
else security_hole(port);
