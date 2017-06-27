#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(35076);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2016/06/30 19:55:38 $");

 script_cve_id("CVE-2008-4032");
 script_bugtraq_id(32638);
 script_osvdb_id(50585);
 script_osvdb_id(50585);
 script_xref(name:"MSFT", value:"MS08-077");
 script_xref(name:"IAVB", value:"2008-B-0082");

 script_name(english:"MS08-077: Vulnerability in Microsoft Office SharePoint Server Could Cause Elevation of Privilege (957175)");
 script_summary(english:"Determines the version of SharePoint");

 script_set_attribute(attribute:"synopsis", value:"A user can elevate his privileges through SharePoint.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of SharePoint Server 2007 that
has a privilege elevation vulnerability in the SharePoint site.

An attacker may use this to execute scripts in the context of the
SharePoint site.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS08-077");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for SharePoint Server 2007.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(287);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/12/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/12/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
 script_set_attribute(attribute:"stig_severity", value:"I");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");

 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0, "KB 'SMB/Registry/Enumerated' not set to TRUE.");


port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();


if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

path = NULL;

# Determine where it's installed.

key = "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\12.0";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
 value = RegQueryValue(handle:key_h, item:"Location");
 if (!isnull(value))
   path = value[1];

 RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);
NetUseDel (close:FALSE);

if (!path)
{
 NetUseDel();
 exit(0);
}

# this file should be included with SharePoint Server 2007, but not
# SharePoint Services (which is not affected)
path += '\\ISAPI\\Microsoft.SharePoint.Publishing.dll';



get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS08-077';
kbs = make_list("956716");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:path);

r = NetUseAdd(share:share);
if ( r != 1 )
{
 NetUseDel();
 audit(AUDIT_SHARE_FAIL, share);
}

handle = CreateFile (file:dll, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) )
 {
  fix = '12.0.6331.5000';
  if (v[0] == 12 && ver_compare(ver:v, fix:fix) == -1)
 {
   info =
     'Product           : Sharepoint Server 2007\n' +
     'Path              : ' + path + '\n' +
     'Installed version : ' + join(v, sep:'.') + '\n' +
     'Fix               : ' + fix + '\n';
   set_kb_item(name:"SMB/Missing/MS08-077", value:TRUE);

   kb       = '956716';
   hotfix_add_report(info, bulletin:bulletin, kb:kb);
   hotfix_security_warning();
 }
 }
}


NetUseDel();
