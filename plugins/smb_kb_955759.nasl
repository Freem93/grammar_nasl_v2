#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(43089);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/09 20:54:59 $");

  script_cve_id(
    "CVE-2009-4210",
    "CVE-2009-4309",
    "CVE-2009-4310",
    "CVE-2009-4311",
    "CVE-2009-4312",
    "CVE-2009-4313"
  );
  script_bugtraq_id(
    37251,
    80529,
    82335,
    82338,
    82341
  );
  script_osvdb_id(
    60855,
    60856,
    60857,
    60858,
    61036,
    61037
  );
  script_xref(name:"IAVB", value:"2009-B-0069");

  script_name(english:"MS KB955759: Security Enhancements for the Indeo Codec");
  script_summary(english:"Checks the version of Aclayers.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update that mitigates multiple
vulnerabilities in a video codec.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing KB955759. This KB mitigates multiple
vulnerabilities in the Indeo video codec by preventing it from being
used by Internet Explorer or Windows Media Player. A remote attacker
can exploit these issues by tricking a user into viewing a maliciously
crafted video file, resulting in the execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/954157");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/kb/955759");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, and
2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94, 119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("audit.inc");
include("misc_func.inc");

ACCESS_DENIED_ACE_TYPE = 0x01;

if (!get_kb_item("SMB/WindowsVersion")) exit(1, "SMB/WindowsVersion KB item is missing.");
if (hotfix_check_sp(win2k:6, xp:4, win2003:3) <= 0) exit(0, "Host is not affected based on its version / service pack.");
if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");

if (
  # Windows 2003 / XP SP2 x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Aclayers.dll", version:"5.2.3790.4624", dir:"\AppPatch") ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Aclayers.dll",  version:"5.1.2600.3637", dir:"\AppPatch") ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Aclayers.dll",  version:"5.1.2600.5906", dir:"\AppPatch") ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0", file:"Aclayers.dll",  version:"5.0.2195.7358", dir:"\AppPatch")
)
{
  # If KB955759 hasn't been applied, check if the relevant DLLs have been
  # 1) unregistered, or 2) deleted
  dlls = make_list(
    'ir32_32.dll',
    'ir41_qc.dll',
    'ir41_qcx.dll',
    'ir50_32.dll',
    'ir50_qc.dll',
    'ir50_qcx.dll'
  );
  share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:hotfix_get_systemroot());
  path = ereg_replace(string:hotfix_get_systemroot(), pattern:'^[A-Za-z]:(.*)', replace:"\1\system32\");
  vuln_dlls = make_list();

  NetUseDel(close:FALSE);
  r = NetUseAdd(login:kb_smb_login(), password:kb_smb_password(), domain:kb_smb_domain(), share:share);
  if ( r != 1 )
  {
    hotfix_check_fversion_end();
    exit(1, "Can't connect to '"+share+"' share.");
  }

  foreach dll (dlls)
  {
    fh = CreateFile(
      file:path + dll,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!fh) continue;  # unable to open file (it was probably deleted)
    
    sd = GetSecurityInfo(handle:fh, level:DACL_SECURITY_INFORMATION);
    if (isnull(sd))
      exit(1, "Unable to access security descriptor for "+path+dll+".");
    
    dacl = sd[3];
    if (isnull(dacl))
      exit(1, "Unable to retrieve DACL for "+path+dll+".");
    
    CloseFile(handle:fh);
    
    dacl = parse_pdacl(blob:dacl);
    if (isnull(dacl))
      exit(1, "Error parsing DACL.");
    
    vuln = make_array();
    
    foreach ace (dacl)
    {
      ace = parse_dacl(blob:ace);
      if (isnull(ace))
      {
        err_print("Error parsing ACE.");
        continue;
      }
    
      rights = ace[0];
      type = ace[3];
      sid = sid2string(sid:ace[1]);
      if (isnull(sid))
      {
        err_print(1, "Error parsing SID.");
        continue;
      }
    
      # Check ACEs for SYSTEM, Users, Power Users, and Administrators
      # only if we haven't already determined whether or not
      # read & execute is allowed
      if (
        (sid == '1-5-18' || sid == '1-5-32-545' ||
         sid == '1-5-32-547' || sid == '1-5-32-544') &&
        !vuln[sid]
      )
      {
        if (
          rights & FILE_GENERIC_READ == FILE_GENERIC_READ &&
          rights & FILE_GENERIC_EXECUTE == FILE_GENERIC_EXECUTE
        ) vuln[sid] = type != ACCESS_DENIED_ACE_TYPE;
      }
    }

    # If read & execute is allowed for any of the SIDs we checked for,
    # the system is vulnerable
    foreach allowed (vuln)
    {
      if (allowed)
      {
        vuln_dlls = make_list(vuln_dlls, dll);
        break;
      }
    }
  }

  if (max_index(vuln_dlls) > 0)
  {
    extra = '\nAdditionally, the following DLLs have not been deleted/unregistered :\n\n';
    foreach dll (vuln_dlls)
      extra += hotfix_get_systemroot()+"\system32\"+dll+'\n';

    hotfix_add_report(extra);
    hotfix_security_hole();
    hotfix_check_fversion_end();
    exit(0);
  }
  else
  {
    hotfix_check_fversion_end();
    exit(0, "KB955759 hasn't been installed, but the Indeo DLLs have been deleted or unregistered, therefore the system is not affected.");
  }
}
else
{
  hotfix_check_fversion_end();
  exit(0, "KB955759 has been installed, therefore the system is not affected.");
}

