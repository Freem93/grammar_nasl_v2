#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79136);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/06/14 04:36:30 $");

  script_cve_id("CVE-2014-6331");
  script_bugtraq_id(70938);
  script_osvdb_id(114529);
  script_xref(name:"MSFT", value:"MS14-077");

  script_name(english:"MS14-077: Vulnerability in Active Directory Federation Services Could Allow Information Disclosure (3003381)");
  script_summary(english:"Checks the version of a DLL file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a vulnerability in the Active
Directory Federation Services (AD FS) that allows an attacker to
obtain unspecified information if a user logs off the application
without closing their browser and an attacker immediately reopens the
application.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-077");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Server 2008, 2008
R2, 2012, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS14-077';
kbs = make_list('3003381');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_NOTE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share()) audit(AUDIT_SHARE_FAIL, share);

sp = get_kb_item("SMB/CSDVersion");
if (sp)
  sp = int(ereg_replace(string:sp, pattern:'.*Service Pack ([0-9]+).*', replace:"\1"));
else sp = 0;

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
windows_ver = get_kb_item_or_exit('SMB/WindowsVersion');
arch = get_kb_item_or_exit('SMB/ARCH');

# Only the 2012 R2 server core is vuln, all other server cores are not.
if (hotfix_check_server_core() == 1 && "2012 R2" >!< productname) audit(AUDIT_WIN_SERVER_CORE);

if ("2008" >!< productname && "2012" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

# initialize SMB
registry_init();

# 2008 SP2 x86 and x64 (KB3003381)
if (windows_ver == "6.0" && sp == 2 && (arch == "x86" || arch == "x64"))
{
  if (arch == "x86")
  {
    check_vuln(
      name : "Active Directory Federation Services 2.0",
      kb   : "3003381",
      path : rootfile + "\assembly\GAC_MSIL\Microsoft.IdentityServer\6.1.0.0__31bf3856ad364e35\microsoft.identityserver.dll",
      fix  : "6.1.7601.18622",
      min_ver : "6.1.7600.16000"
    );
    if (!vuln)
    {
      check_vuln(
        name : "Active Directory Federation Services 2.0",
        kb   : "3003381",
        path : rootfile + "\assembly\GAC_MSIL\Microsoft.IdentityServer\6.1.0.0__31bf3856ad364e35\microsoft.identityserver.dll",
        fix  : "6.1.7601.22828",
        min_ver : "6.1.7601.20000"
      );
    }
  }
  else # x64
  {
    check_vuln(
      name : "Active Directory Federation Services 2.0",
      kb   : "3003381",
      path : rootfile + "\assembly\GAC_MSIL\Microsoft.IdentityServer\6.1.0.0__31bf3856ad364e35\microsoft.identityserver.dll",
      fix  : "6.1.7601.18620",
      min_ver : "6.1.7600.16000"
    );
    if (!vuln)
    {
      check_vuln(
        name : "Active Directory Federation Services 2.0",
        kb   : "3003381",
        path : rootfile + "\assembly\GAC_MSIL\Microsoft.IdentityServer\6.1.0.0__31bf3856ad364e35\microsoft.identityserver.dll",
        fix  : "6.1.7601.22827",
        min_ver : "6.1.7601.20000"
      );
    }
  }
}
# Server 2008 R2 SP1 x64 only (KB3003381)
else if (windows_ver == "6.1" && sp == 1 && arch == "x64")
{
  check_vuln(
    name : "Active Directory Federation Services 2.0",
    kb   : "3003381",
    path : rootfile + "\assembly\GAC_MSIL\Microsoft.IdentityServer\6.1.0.0__31bf3856ad364e35\microsoft.identityserver.dll",
    fix  : "6.1.7601.18620",
    min_ver : "6.1.7600.16000"
  );
  if (!vuln)
  {
    check_vuln(
      name : "Active Directory Federation Services 2.0",
      kb   : "3003381",
      path : rootfile + "\assembly\GAC_MSIL\Microsoft.IdentityServer\6.1.0.0__31bf3856ad364e35\microsoft.identityserver.dll",
      fix  : "6.1.7601.22827",
      min_ver : "6.1.7601.20000"
    );
  }
}
# Server 2012 (KB3003381)
else if (windows_ver == "6.2" && sp == 0)
{
  check_vuln(
    name : "Active Directory Federation Services 2.1",
    kb   : "3003381",
    path : rootfile + "\Microsoft.NET\assembly\GAC_MSIL\Microsoft.IdentityServer\v4.0_6.2.0.0__31bf3856ad364e35\microsoft.identityserver.dll",
    fix  : "6.2.9200.17135",
    min_ver : "6.2.9200.16000"
  );
  check_vuln(
    name : "Active Directory Federation Services 2.1",
    kb   : "3003381",
    path : rootfile + "\Microsoft.NET\assembly\GAC_MSIL\Microsoft.IdentityServer\v4.0_6.2.0.0__31bf3856ad364e35\microsoft.identityserver.dll",
    fix  : "6.2.9200.21252",
    min_ver : "6.2.9200.20000"
  );
}
# Server 2012 R2 (KB3003381)
else if (windows_ver == "6.3" && sp == 0)
{
  check_vuln(
    name : "Active Directory Federation Services 3.0",
    kb   : "3003381",
    path : rootfile + "\Microsoft.NET\assembly\GAC_MSIL\Microsoft.IdentityServer.Diagnostics\v4.0_6.3.0.0__31bf3856ad364e35\microsoft.identityserver.diagnostics.dll",
    fix  : "6.3.9600.17412",
    min_ver : "6.3.9600.16000"
  );
}

hotfix_check_fversion_end();

if (!vuln) audit(AUDIT_HOST_NOT, 'affected');

# Flag the system as vulnerable
set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
hotfix_security_note();
