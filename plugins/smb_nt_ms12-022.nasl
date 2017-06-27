#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58334);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2012-0016");
  script_bugtraq_id(52375);
  script_osvdb_id(80001);
  script_xref(name:"MSFT", value:"MS12-022");
  script_xref(name:"IAVA", value:"2012-A-0038");

  script_name(english:"MS12-022: Vulnerability in Expression Design Could Allow Remote Code Execution (2651018)");
  script_summary(english:"Checks version of GraphicsCore.dll");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Expression Design install on the remote Windows host
could allow arbitrary code execution.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Expression Design installed on the remote
host is reportedly affected by an insecure library loading
vulnerability.

A remote attacker could exploit this flaw by tricking a user into
opening a legitimate .xpr or .DESIGN file located in the same
directory as a maliciously crafted dynamic link library (DLL) file,
resulting in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-022");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Expression Design.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:expression_design");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS12-022';
kbs = make_list('2675064', '2667724', '2667725', '2667727', '2667730');
if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

hcf_init = TRUE;

# Connect to remote registry.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

# Check for Microsoft Expression installs
paths = make_list();

key = 'SOFTWARE\\Microsoft\\Expression\\Design';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:'InstallDir');
  if (!isnull(value)) paths = make_list(paths, value[1]);

  # In some cases, the Install info is stored in a subkey
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ '^[0-9\\.]+$')
    {
      key2 = key + '\\' + subkey;
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:'InstallDir');
        if (!isnull(value)) paths = make_list(paths, value[1]);

        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if (max_index(paths) == 0)
{
  NetUseDel();
  exit(0, 'No evidence of Microsoft Expression Design found in the registry.');
}

# Loop through and check each install
vuln = 0;
foreach path (paths)
{
  share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
  dll = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\GraphicsCore.dll', string:path);

  NetUseDel(close:FALSE);

  if (!is_accessible_share(share:share)) exit(1, 'is_accessible_share() failed.');
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }

  if (
    # Expression Design
    #hotfix_is_vulnerable(path:path, file:'GraphicsCore.dll', version:'4.0.2712.1', min_version:'4.0.0.0', bulletin:bulletin, kb:'2675064') ||
    # Expression Design SP1
    #hotfix_is_vulnerable(path:path, file:'GraphicsCore.dll', version:'4.0.2920.1', min_version:'4.0.2900.0', bulletin:bulletin, kb:'2667724') ||
    # Expression Design 2
    #hotfix_is_vulnerable(path:path, file:'GraphicsCore.dll', version:'5.0.1379.1', min_version:'5.0.0.0', bulletin:bulletin, kb:'2667725') ||

    # Expression Design 3
    hotfix_is_vulnerable(path:path, file:'GraphicsCore.dll', version:'6.0.1746.0', min_version:'6.0.0.0', bulletin:bulletin, kb:'2667727') ||

    # Expression Design 4
    hotfix_is_vulnerable(path:path, file:'GraphicsCore.dll', version:'7.0.30202.0', min_version:'7.0.0.0', bulletin:bulletin, kb:'2667730')
  )
  {
    vuln++;
  }
}

hotfix_check_fversion_end();

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else exit(0, 'The host is not affected.');
