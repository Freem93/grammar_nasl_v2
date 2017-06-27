#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(26022);
 script_version("$Revision: 1.30 $");
 script_cvs_date("$Date: 2015/12/01 15:02:05 $");

 script_cve_id("CVE-2006-6133");
 script_bugtraq_id(21261);
 script_osvdb_id(31704);
 script_xref(name:"MSFT", value:"MS07-052");
 script_xref(name:"EDB-ID", value:"29171");

 script_name(english:"MS07-052: Vulnerability in Crystal Reports for Visual Studio Could Allow Remote Code Execution (941522)");
 script_summary(english:"Determines the version of visual studio");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Visual
Studio.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Visual Studio that
may allow arbitrary code to be run.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it. Then a bug in the RPT parsing
handler would result in code execution.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-052");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Visual Studio 2002, 2003
and 2005.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/02");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/09/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/12");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_.net");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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

bulletin = 'MS07-052';
kbs = make_list("937057", "937058", "937060");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

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

path = vs = NULL;

# Determine where it's installed.

key = "SOFTWARE\Microsoft\VisualStudio\8.0\Packages\{97358C99-E52D-42C7-8B7C-B59CC4425F4B}";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
 vs = "8.0";
}
else
{
 key = "SOFTWARE\Microsoft\VisualStudio\7.1\Packages\{A9D28E15-E2CD-4185-A9BE-7DC617936ACB}";
 key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
 if (!isnull(key_h))
 {
  vs = "7.1";
 }
 else
 {
  key = "SOFTWARE\Microsoft\VisualStudio\7.0\Packages\{F05E92C6-8346-11D3-B4AD-00A0C9B04E7B}";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
   vs = "7.0";
  }
 }
}


if (!isnull(key_h))
{
 value = RegQueryValue(handle:key_h, item:"InprocServer32");
 if (!isnull(value))
   path = value[1];

 RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);
NetUseDel (close:FALSE);

if (!path || !vs)
{
 NetUseDel();
 exit(0);
}

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:path);


r = NetUseAdd(share:share);
if ( r != 1 )
{
 NetUseDel();
 audit(AUDIT_SHARE_FAIL,share);
}

handle = CreateFile (file:dll, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);

 if ( ! isnull(v) )
 {
  if (
    (vs == "8.0") &&
    (v[0] == 10 && v[1] == 2 && v[2] == 0 && v[3] < 1222)
  )
  {
    hotfix_add_report('\nPath : '+share-'$'+':'+dll+
                      '\nVersion : '+join(v, sep:'.')+
                      '\nShould be : 10.2.0.1222\n',
                      bulletin:bulletin,
                      kb:'937060');  # also KB937061
    set_kb_item(name:"SMB/Missing/MS07-052", value:TRUE);
    hotfix_security_hole();
  }
  else if (
    (vs == "7.1") &&
    ((v[0] == 9 && v[1] < 1) || (v[0] == 9 && v[1] == 1 && v[2] < 2) || (v[0] == 9 && v[1] == 1 && v[2] == 2 && v[3] < 1871))
  )
  {
    hotfix_add_report('\nPath : '+share-'$'+':'+dll+
                      '\nVersion : '+join(v, sep:'.')+
                      '\nShould be : 9.1.2.1871\n',
                      bulletin:bulletin,
                      kb:'937058');  # also KB937059
    set_kb_item(name:"SMB/Missing/MS07-052", value:TRUE);
    hotfix_security_hole();
  }
  else if (
    (vs == "7.0") &&
    ((v[0] == 9 && v[1] < 1) || (v[0] == 9 && v[1] == 1 && v[2] == 0 && v[3] < 2004))
  )
  {
    hotfix_add_report('\nPath : '+share-'$'+':'+dll+
                      '\nVersion : '+join(v, sep:'.')+
                      '\nShould be : 9.1.0.2004\n',
                      bulletin:bulletin,
                      kb:'937057');
    set_kb_item(name:"SMB/Missing/MS07-052", value:TRUE);
    hotfix_security_hole();
  }
 }
}


NetUseDel();
