#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(34120);
 script_version("$Revision: 1.37 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id(
   "CVE-2007-5348",
   "CVE-2008-3012",
   "CVE-2008-3013",
   "CVE-2008-3014",
   "CVE-2008-3015"
 );
 script_bugtraq_id(31018, 31019, 31020, 31021, 31022);
 script_osvdb_id(47965, 47966, 47967, 47968, 47969);
 script_xref(name:"MSFT", value:"MS08-052");

 script_name(english:"MS08-052: Vulnerabilities in GDI+ Could Allow Remote Code Execution (954593)");
 script_summary(english:"Determines the presence of update 954593");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the
Microsoft GDI rendering engine.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows that has multiple
buffer overflow vulnerabilities when viewing VML, EMF, GIF, WMF and
BMP files that could allow an attacker to execute arbitrary code on
the remote host.

To exploit these flaws, an attacker would need to send a malformed
image file to a user on the remote host and wait for him to open it
using an affected Microsoft application.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms08-052");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(119, 189, 399);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/09/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "mssql_version.nasl", "smb_nt_ms02-031.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS08-052';
kbs = make_list("938464", "954326", "954478", "954479", "954606");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

patched = 0;

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");


share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
lastshare = share;
accessibleshare = FALSE;
path = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:rootfile);

login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (r != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

accessibleshare = TRUE;
paths = make_list (
      "\WinSxS\Policies\x86_policy.1.0.Microsoft.Windows.GdiPlus_6595b64144ccf1df_x-ww_4e8510ac",
      "\WinSxS\Policies\amd64_policy.1.0.Microsoft.Windows.GdiPlus_6595b64144ccf1df_x-ww_AE43B2CC"
      );

foreach spath (paths)
{
 spath = path + spath;
 handle =  CreateFile (file:spath, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_DIRECTORY, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
 if ( ! isnull(handle) )
 {
  patched++;
  CloseFile(handle:handle);
  break;
 }
}

NetUseDel();

vuln = 0;
office_versions = hotfix_check_office_version ();
visio_versions = get_kb_item("SMB/Office/Visio/*/VisioPath");

cdir = hotfix_get_commonfilesdir();

if (is_accessible_share())
{
 if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:2) > 0)
 {
   kb = '938464';
   # Windows 2000, XP, 2003, Vista, 2008 and IE 6
   if ( !patched &&
      ( hotfix_is_vulnerable(os:"6.0", sp:0, file:"Gdiplus.dll", version:"5.2.6000.16683", dir:"\system32", bulletin:bulletin, kb:kb) ||
        hotfix_is_vulnerable(os:"6.0", sp:0, file:"Gdiplus.dll", version:"5.2.6000.20826", min_version:"5.2.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
        hotfix_is_vulnerable(os:"6.0", sp:0, file:"Gdiplus.dll", version:"6.0.6000.16683", min_version:"6.0.6000.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
        hotfix_is_vulnerable(os:"6.0", sp:0, file:"Gdiplus.dll", version:"6.0.6000.20826", min_version:"6.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
        hotfix_is_vulnerable(os:"6.0", sp:1, file:"Gdiplus.dll", version:"5.2.6001.18065", dir:"\system32", bulletin:bulletin, kb:kb) ||
        hotfix_is_vulnerable(os:"6.0", sp:1, file:"Gdiplus.dll", version:"5.2.6001.22170", min_version:"5.2.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
        hotfix_is_vulnerable(os:"6.0", sp:1, file:"Gdiplus.dll", version:"6.0.6001.18065", min_version:"6.0.6001.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
        hotfix_is_vulnerable(os:"6.0", sp:1, file:"Gdiplus.dll", version:"6.0.6001.22170", min_version:"6.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
        hotfix_is_vulnerable(os:"5.2", sp:1, file:"Gdiplus.dll", version:"5.2.3790.3126", dir:"\system32", bulletin:bulletin, kb:kb) ||
        hotfix_is_vulnerable(os:"5.2", sp:2, file:"Gdiplus.dll", version:"5.2.3790.4278", dir:"\system32", bulletin:bulletin, kb:kb) ||
        hotfix_is_vulnerable(os:"5.1", sp:2, file:"Gdiplus.dll", version:"5.1.3102.3352", dir:"\system32", bulletin:bulletin, kb:kb) ||
        hotfix_is_vulnerable(os:"5.1", sp:3, file:"Gdiplus.dll", version:"5.1.3102.5581", dir:"\system32", bulletin:bulletin, kb:kb) ||
        hotfix_is_vulnerable(os:"5.0", file:"Gdiplus.dll", version:"5.1.3102.3352", dir:"\system32", bulletin:bulletin, kb:kb) ||
        hotfix_is_vulnerable(os:"5.0", file:"Vgx.dll", version:"6.0.2800.1612", min_version:"6.0.0.0", dir:"\Microsoft Shared\VGX", path:cdir, bulletin:bulletin, kb:kb) )
      )
   {
    vuln++;
   }
 }
}

# Office 2003
if (office_versions["11.0"])
{
  path = hotfix_get_officeprogramfilesdir(officever:"11.0") + "\Microsoft Office\OFFICE11";
  share = hotfix_path2share(path:path);
  if (share != lastshare || !accessibleshare)
  {
    lastshare = share;
    if (is_accessible_share(share:share)) accessibleshare = TRUE;
  }
  if (accessibleshare)
  {
    if ( hotfix_check_fversion(file:"Gdiplus.dll", version:"11.0.8230.0", path:path, bulletin:bulletin, kb:'954478') == HCF_OLDER )
    {
      vuln++;
    }
  }
}

# Office 2007
if (office_versions["12.0"])
{
  path = hotfix_get_commonfilesdir() + "\Microsoft Shared\OFFICE12";
  share = hotfix_path2share(path:path);
  if (share != lastshare || !accessibleshare)
  {
    lastshare = share;
    if (is_accessible_share(share:share)) accesibleshare = TRUE;
  }
  if (accessibleshare)
  {
    if ( hotfix_check_fversion(file:"Ogl.dll", version:"12.0.6325.5000", path:path, bulletin:bulletin, kb:'954326') == HCF_OLDER )
    {
      vuln++;
    }
  }
}

# Visio 2002
foreach visio_version (keys(visio_versions))
{
  if ("10.0" >< visio_version)
  {
    path = hotfix_get_commonfilesdir() + "\Microsoft Shared\OFFICE10";
    share = hotfix_path2share(path:path);
    if (share != lastshare || !accessibleshare)
    {
      lastshare = share;
      if (is_accessible_share(share:share)) accessibleshare = TRUE;
    }
    if (accessibleshare)
    {
      if ( hotfix_check_fversion(file:"Mso.dll", version:"10.0.6844.0", path:path, bulletin:bulletin, kb:'954479') == HCF_OLDER )
      {
        vuln++;
      }
    }
    break;
  }
}

# SQL server 2005
kb = '954606';
if ( ( hotfix_check_fversion(path:rootfile, file:"Sqlservr.exe", version:"2005.90.3073.0", min_version:"2005.90.3000.0", bulletin:bulletin, kb:kb) == HCF_OLDER ) ||
   ( hotfix_check_fversion(path:rootfile, file:"Sqlservr.exe", version:"2005.90.3282.0", min_version:"2005.90.3200.0", bulletin:bulletin, kb:kb) == HCF_OLDER ) )
{
  vuln++;
}

hotfix_check_fversion_end();
if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
