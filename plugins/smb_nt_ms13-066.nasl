#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69331);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/06 17:11:38 $");

  script_cve_id("CVE-2013-3185");
  script_bugtraq_id(61672);
  script_osvdb_id(96181);
  script_xref(name:"MSFT", value:"MS13-066");
  script_xref(name:"IAVB", value:"2013-B-0087");

  script_name(english:"MS13-066: Vulnerability in Active Directory Federation Services Could Allow Information Disclosure (2873872)");
  script_summary(english:"Checks the version of a DLL file");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by an unspecified vulnerability in
the Active Directory Federation Services (AD FS) that may allow an
attacker to obtain the AD FS instance account information.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-066");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Server 2003 R2,
2008, 2008 R2, and 2012.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

global_var bulletin, vuln;

function get_ver()
{
  local_var fh, path, rc, share, ver;

  path = _FCT_ANON_ARGS[0];

  share = hotfix_path2share(path:path);

  rc = NetUseAdd(share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }

  ver = NULL;
  path = ereg_replace(string:path, pattern:"^[A-Za-z]:(.*)", replace:'\\1\\');

  fh = CreateFile(
    file               : path,
    desired_access     : GENERIC_READ,
    file_attributes    : FILE_ATTRIBUTE_NORMAL,
    share_mode         : FILE_SHARE_READ,
    create_disposition : OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    ver = join(ver, sep:".");
    CloseFile(handle:fh);
  }

  NetUseDel(close:FALSE);

  return ver;
}

function check_vuln(fix, kb, name, path, ver, min_ver)
{
  local_var info;

  if (isnull(ver))
    ver = get_ver(path);

  if (isnull(ver) || ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
    return 0;

  # If min_ver is supplied, make sure the version is higher than the min_ver
  if (min_ver && ver_compare(ver:ver, fix:min_ver, strict:FALSE) == -1)
    return 0;

  info =
    '\n  Product           : ' + name +
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix + '\n';
  hotfix_add_report(info, bulletin:bulletin, kb:kb);

  vuln = TRUE;
}

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS13-066';
kbs = make_list('2868846', '2843638', '2843639');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if(!is_accessible_share()) audit(AUDIT_SHARE_FAIL, share);

sp = get_kb_item("SMB/CSDVersion");
if (sp)
  sp = int(ereg_replace(string:sp, pattern:'.*Service Pack ([0-9]+).*', replace:"\1"));
else sp = 0;

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
windows_ver = get_kb_item_or_exit('SMB/WindowsVersion');
arch = get_kb_item_or_exit('SMB/ARCH');

# initialize SMB
registry_init();

# Server 2003 R2 (only R2 is affected)
if(windows_ver == "5.2" && "2003 R2" >< productname && sp == 2)
{
  check_vuln(
    name : "Active Directory Federation Services 1.x",
    kb   : "2868846",
    path : rootfile + "\assembly\GAC_MSIL\System.Web.Security.SingleSignOn\1.0.0.0__31bf3856ad364e35\System.Web.Security.SingleSignOn.dll",
    fix  : "5.2.3790.5190"
  );
}
# 2008 SP2 x86 and x64 (KB2843638 & KB2868846)
else if(windows_ver == "6.0" && sp == 2 && (arch == "x86" || arch == "x64"))
{
  check_vuln(
    name : "Active Directory Federation Services 1.x",
    kb   : "2868846",
    path : rootfile + "\assembly\GAC_MSIL\System.Web.Security.SingleSignOn\1.0.0.0__31bf3856ad364e35\System.Web.Security.SingleSignOn.dll",
    fix  : "6.0.6002.18880",
    min_ver : "6.0.6002.16000"
  );
  check_vuln(
    name : "Active Directory Federation Services 1.x",
    kb   : "2868846",
    path : rootfile + "\assembly\GAC_MSIL\System.Web.Security.SingleSignOn\1.0.0.0__31bf3856ad364e35\System.Web.Security.SingleSignOn.dll",
    fix  : "6.0.6002.23152",
    min_ver : "6.0.6002.20000"
  );
  if(arch == "x86")
  {
    check_vuln(
      name : "Active Directory Federation Services 2.0",
      kb   : "2843638",
      path : rootfile + "\assembly\GAC_MSIL\Microsoft.IdentityServer\6.1.0.0__31bf3856ad364e35\microsoft.identityserver.dll",
      fix  : "6.1.7600.17338",
      min_ver : "6.1.7600.16000"
    );
  }
  else # x64
  {
    check_vuln(
      name : "Active Directory Federation Services 2.0",
      kb   : "2843638",
      path : rootfile + "\assembly\GAC_MSIL\Microsoft.IdentityServer\6.1.0.0__31bf3856ad364e35\microsoft.identityserver.dll",
      fix  : "6.1.7600.17337",
      min_ver : "6.1.7600.16000"
    );
  }
  check_vuln(
    name : "Active Directory Federation Services 2.0",
    kb   : "2843638",
    path : rootfile + "\assembly\GAC_MSIL\Microsoft.IdentityServer\6.1.0.0__31bf3856ad364e35\microsoft.identityserver.dll",
    fix  : "6.1.7601.22371",
    min_ver : "6.1.7600.20000"
  );
}
# Server 2008 R2 SP1 (KB2868846 & KB2843638)
else if(windows_ver == "6.1" && sp == 1 && arch == "x64")
{
  check_vuln(
    name : "Active Directory Federation Services 1.x",
    kb   : "2868846",
    path : rootfile + "\assembly\GAC_MSIL\System.Web.Security.SingleSignOn\1.0.0.0__31bf3856ad364e35\System.Web.Security.SingleSignOn.dll",
    fix  : "6.1.7601.18199",
    min_ver : "6.1.7600.16000"
  );
  check_vuln(
    name : "Active Directory Federation Services 1.x",
    kb   : "2868846",
    path : rootfile + "\assembly\GAC_MSIL\System.Web.Security.SingleSignOn\1.0.0.0__31bf3856ad364e35\System.Web.Security.SingleSignOn.dll",
    fix  : "6.1.7601.22375",
    min_ver : "6.1.7601.20000"
  );
  check_vuln(
    name : "Active Directory Federation Services 2.0",
    kb   : "2843638",
    path : rootfile + "\assembly\GAC_MSIL\Microsoft.IdentityServer\6.1.0.0__31bf3856ad364e35\microsoft.identityserver.dll",
    fix  : "6.1.7601.18235",
    min_ver : "6.1.7600.16000"
  );
  check_vuln(
    name : "Active Directory Federation Services 2.0",
    kb   : "2843638",
    path : rootfile + "\assembly\GAC_MSIL\Microsoft.IdentityServer\6.1.0.0__31bf3856ad364e35\microsoft.identityserver.dll",
    fix  : "6.1.7601.22420",
    min_ver : "6.1.7601.20000"
  );
}
# Server 2012 (KB2843638 & KB2843639)
else if(windows_ver == "6.2" && sp == 0)
{
  check_vuln(
    name : "Active Directory Federation Services 2.1",
    kb   : "2843638",
    path : rootfile + "\Microsoft.NET\assembly\GAC_MSIL\Microsoft.IdentityServer\v4.0_6.2.0.0__31bf3856ad364e35\microsoft.identityserver.dll",
    fix  : "6.2.9200.16645",
    min_ver : "6.2.9200.16000"
  );
  check_vuln(
    name : "Active Directory Federation Services 2.1",
    kb   : "2843639",
    path : rootfile + "\Microsoft.NET\assembly\GAC_MSIL\Microsoft.IdentityServer\v4.0_6.2.0.0__31bf3856ad364e35\microsoft.identityserver.dll",
    fix  : "6.2.9200.16651",
    min_ver : "6.2.9200.16000"
  );
  check_vuln(
    name : "Active Directory Federation Services 2.1",
    kb   : "2843638",
    path : rootfile + "\Microsoft.NET\assembly\GAC_MSIL\Microsoft.IdentityServer\v4.0_6.2.0.0__31bf3856ad364e35\microsoft.identityserver.dll",
    fix  : "6.2.9200.20752",
    min_ver : "6.2.9200.20000"
  );
  check_vuln(
    name : "Active Directory Federation Services 2.1",
    kb   : "2843639",
    path : rootfile + "\Microsoft.NET\assembly\GAC_MSIL\Microsoft.IdentityServer\v4.0_6.2.0.0__31bf3856ad364e35\microsoft.identityserver.dll",
    fix  : "6.2.9200.20760",
    min_ver : "6.2.9200.20000"
  );
}

hotfix_check_fversion_end();

if (!vuln) audit(AUDIT_HOST_NOT, 'affected');

# Flag the system as vulnerable
set_kb_item(name:"SMB/Missing/" + bulletin, value:TRUE);
hotfix_security_warning();
