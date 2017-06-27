#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22535);
 script_version("$Revision: 1.38 $");
 script_cvs_date("$Date: 2016/07/11 14:12:52 $");

 script_cve_id(
  "CVE-2006-3434",
  "CVE-2006-3650",
  "CVE-2006-3864",
  "CVE-2006-3868"
 );
 script_bugtraq_id(20320, 20382, 20383, 20384);
 script_osvdb_id(29427, 29428, 29429, 29430);
 script_xref(name:"CERT", value:"534276");
 script_xref(name:"CERT", value:"807780");
 script_xref(name:"MSFT", value:"MS06-062");

 script_name(english:"MS06-062: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (922581)");
 script_summary(english:"Determines the version of MSO.dll");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Office.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Office that could
allow arbitrary code to be run.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it with Microsoft Office.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-062");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office 2000, XP and 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/10");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/10/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:access");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:frontpage");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:infopath");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:onenote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:publisher");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project");
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

bulletin = 'MS06-062';
kbs = make_list("922581", "923272", "923273", "923274");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


kb = '922581';

get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

office_versions = hotfix_check_office_version ();
if ( !office_versions ) exit(0, "Microsoft Office not found.");

rootfiles = hotfix_get_officecommonfilesdir();
if ( ! rootfiles ) exit(1, "Failed to get Office Common Files directory.");

login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

share = '';
lastshare = '';
vuln = FALSE;
checkedfiles = make_array();
foreach ver (keys(office_versions))
{
  if (typeof(rootfiles) == 'array') rootfile = rootfiles[ver];
  else rootfile = rootfiles;
  if ( "9.0" >< ver )
	{
    rootfile = hotfix_get_programfilesdir();
    dll  =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Office\Office\mso9.dll", string:rootfile);
	}
  else if ( "10.0" >< ver )
  {
	  dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Shared\Office10\mso.dll", string:rootfile);
  }
  else if ( "11.0" >< ver )
  {
	  dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Shared\Office11\mso.dll", string:rootfile);
  }
  else continue;
  if (checkedfiles[dll]) continue;

  share = hotfix_path2share(path:rootfile);
  if (share && share != lastshare)
  {
    NetUseDel(close:FALSE);
    r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if ( r != 1 ) audit(AUDIT_SHARE_FAIL,share);
  }

  handle =  CreateFile (file:dll, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

  if ( ! isnull(handle) )
  {
    checkedfiles[dll] = 1;
    v = GetFileVersion(handle:handle);
    CloseFile(handle:handle);
    if ( !isnull(v) )
    {
      if (v[0] == 9 &&  v[1] == 0 && v[2] == 0 && v[3] < 8950)
      {
        vuln = TRUE;
        kb = '923274';
        hotfix_add_report('\nPath : '+share-'$'+':'+dll+
                          '\nVersion : '+join(v, sep:'.')+
                          '\nShould be : 9.0.0.8950\n',
                          bulletin:bulletin, kb:kb);
      }
      else if (v[0] == 10 && v[1] == 0 && v[2] < 6817)
      {
        vuln = TRUE;
        kb = '923273';
        hotfix_add_report('\nPath : '+share-'$'+':'+dll+
                          '\nVersion : '+join(v, sep:'.')+
                          '\nShould be : 10.0.6817.0\n',
                          bulletin:bulletin, kb:kb);
      }
      else if ( v[0] == 11 && v[1] == 0 && v[2] < 8107)
      {
        vuln = TRUE;
        kb = '923272';
        hotfix_add_report('\nPath : '+share-'$'+':'+dll+
                          '\nVersion : '+join(v, sep:'.')+
                          '\nShould be : 11.0.8107.0\n',
                          bulletin:bulletin, kb:kb);
      }
    }
  }
}
NetUseDel();
if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
