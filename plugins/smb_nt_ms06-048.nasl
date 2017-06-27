#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22190);
 script_version("$Revision: 1.37 $");
 script_cvs_date("$Date: 2016/06/30 19:55:38 $");

 script_cve_id("CVE-2006-3590", "CVE-2006-3449");
 script_bugtraq_id(19341);
 script_osvdb_id(27324, 29143);
 script_xref(name:"CERT", value:"936945");
 script_xref(name:"CERT", value:"884252");
 script_xref(name:"MSFT", value:"MS06-048");

 script_name(english:"MS06-048: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (922968)");
 script_summary(english:"Determines the version of MSO.dll");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Office.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Office that could
allow arbitrary code execution.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have him open it with Microsoft Office.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-048");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office 2000, XP and 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/08/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/08");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
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

bulletin = 'MS06-048';
kbs = make_list("921566", "921567", "921568", "922968");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


kb = '922968';

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
checkedfiles = make_array();
foreach ver (keys(office_versions))
{
  if (typeof(rootfiles) == 'array') rootfile = rootfiles[ver];
  else rootfile = rootfiles;
  if ("9.0" >< ver)
  {
	  rootfile = hotfix_get_programfilesdir();
  	dll  =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Office\Office\mso9.dll", string:rootfile);
	}
  else if ("10.0" >< ver )
  {
	  dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Shared\Office10\mso.dll", string:rootfile);
  }
  else if ( "11.0" >< ver )
  {
  	dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Shared\Office11\mso.dll", string:rootfile);
  }
  if (checkedfiles[dll]) continue;

  share = hotfix_path2share(path:rootfile);
  if (share && lastshare != share)
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
      if (v[0] == 9 &&  v[1] == 0 && v[2] == 0 && v[3] < 8948)
      {
        vuln = TRUE;
        kb = '921568';
        hotfix_add_report('\nPath : '+share-'$'+':'+dll+
                          '\nVersion : '+join(v, sep:'.')+
                          '\nShould be : 9.0.0.8948\n',
                          bulletin:bulletin, kb:kb);
      }
      else if (v[0] == 10 && v[1] == 0 && v[2] < 6811)
      {
        vuln = TRUE;
        kb = '921567';
        hotfix_add_report('\nPath : '+share-'$'+':'+dll+
                          '\nVersion : '+join(v, sep:'.')+
                          '\nShould be : 10.0.6811.0\n',
                          bulletin:bulletin, kb:kb);
      }
      else if (v[0] == 11 && v[1] == 0 && v[2] < 8036)
      {
        vuln = TRUE;
        kb = '921566';
        hotfix_add_report('\nPath : '+share-'$'+':'+dll+
                          '\nVersion : '+join(v, sep:'.')+
                          '\nShould be : 11.0.8036.0\n',
                          bulletin:bulletin, kb:kb);
      }
    }
  }
}
NetUseDel();
if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
