#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(23836);
 script_version("$Revision: 1.32 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id("CVE-2006-4704");
 script_bugtraq_id(20843);
 script_osvdb_id(30155);
 script_xref(name:"CERT", value:"854856");
 script_xref(name:"MSFT", value:"MS06-073");

 script_name(english:"MS06-073: Vulnerability in Visual Studio 2005 Could Allow Remote Code Execution (925674)");
 script_summary(english:"Determines the version of visual studio");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
browser.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Visual Studio 2005
that is vulnerable to a buffer overflow when handling malformed WMI
request in the ActiveX component.

An attacker may exploit this flaw to execute arbitrary code on this
host, by entice a use to visit a specially crafter web page.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-073");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for VS2005.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'MS06-014 Microsoft Internet Explorer COM CreateObject Code Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/01");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/12/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/12");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS06-073';
kb = '925674';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


common = hotfix_get_commonfilesdir();
if ( ! common ) exit(1, "Failed to get the Common Files directory.");

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
  audit(AUDIT_SHARE_FAIL,"IPC$");
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}


# Determine where it's installed.
key = "SOFTWARE\Microsoft\VisualStudio\8.0";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);


if (isnull(key_h))
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}
else
{
 RegCloseKey(handle:key_h);
 RegCloseKey(handle:hklm);
 NetUseDel (close:FALSE);
}

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:common);
wmi =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Shared\WMI\wmiscriptutils.dll", string:common);


r = NetUseAdd(share:share);
if ( r != 1 )
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

handle = CreateFile (file:wmi, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) )
 {
  if ( v[0] == 8 && v[1] == 0 && ( (v[2] < 50727 ) || ( v[2] == 50727 && v[3] < 236 ) ) )
 {
 hotfix_add_report('\nPath : '+share-'$'+':'+wmi+
                   '\nVersion : '+join(v, sep:'.')+
                   '\nShould be : 8.0.50727.236\n',
                   bulletin:bulletin, kb:kb);
 set_kb_item(name:"SMB/Missing/MS06-073", value:TRUE);
 hotfix_security_warning();
 }
 }
}


NetUseDel();
