#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18489);
 script_version("$Revision: 1.37 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id("CVE-2005-1213");
 script_bugtraq_id(13951);
 script_osvdb_id(17306);
 script_xref(name:"MSFT", value:"MS05-030");
 script_xref(name:"CERT", value:"130614");
 script_xref(name:"EDB-ID", value:"1066");
 script_xref(name:"EDB-ID", value:"16379");

 script_name(english:"MS05-030: Vulnerability in Outlook Express Could Allow Remote Code Execution (897715)");
 script_summary(english:"Determines the version of MSOE.dll");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the email
client.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Outlook Express that
could allow an attacker to execute arbitrary code on the remote host.

To exploit this flaw, an attacker would need to lure a user to connect
to a rogue NNTP (news) server sending malformed replies to several
queries.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms05-030");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Outlook Express.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'MS05-030 Microsoft Outlook Express NNTP Response Parsing Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/06/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/14");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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

bulletin = 'MS05-030';
kb = '897715';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

rootfile = hotfix_get_programfilesdir();
if ( ! rootfile ) exit(1, "Failed to get the Program Files directory.");

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Outlook Express\msoe.dll", string:rootfile);




login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 )
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}


handle =  CreateFile (file:dll, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( ! isnull(handle) )
{
 flag = 0;
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 set_kb_item(name:"SMB/OutlookExpress/MSOE.dll/Version", value:string(v[0], ".", v[1], ".", v[2], ".", v[3]));

 if ( hotfix_check_sp(xp:2, win2k:5, win2003:1) <= 0 ) {
	NetUseDel();
	exit(0);
	}

 if ( v[0] == 5 )
	{
	 if ( (v[0] == 5 && v[1] < 50) ||
	      (v[0] == 5 && v[1] == 50 && v[2] < 4952) ||
	      (v[0] == 5 && v[1] == 50 && v[2] == 4952 && v[3] < 2800 ) ) { {
 hotfix_add_report('\nPath : '+share-'$'+':'+dll+
                   '\nVersion : '+join(v, sep:'.')+
                   '\nShould be : 5.50.4952.2800\n', bulletin:bulletin, kb:kb);
 set_kb_item(name:"SMB/Missing/MS05-030", value:TRUE);
 hotfix_security_hole();
 }flag ++; }
	}
 else if ( v[0] == 6 )
	{
	 if ( ( v[0] == 6 && v[1] == 0 && v[2] < 2800) ||
	      ( v[0] == 6 && v[1] == 0 && v[2] == 2800 && v[3] < 1506 ) ) { {
 hotfix_add_report('\nPath : '+share-'$'+':'+dll+
                   '\nVersion : '+join(v, sep:'.')+
                   '\nShould be : 6.0.2800.1506\n', bulletin:bulletin, kb:kb);
 set_kb_item(name:"SMB/Missing/MS05-030", value:TRUE);
 hotfix_security_hole();
 }flag ++; }

	  if( ( v[0] == 6 && v[1] == 0 && v[2] > 2800 && v[2] < 3790 ) ||
	      ( v[0] == 6 && v[1] == 0 && v[2] == 3790 && v[3] < 326 ) ) { {
 hotfix_add_report('\nPath : '+share-'$'+':'+dll+
                   '\nVersion : '+join(v, sep:'.')+
                   '\nShould be : 6.0.3790.326\n', bulletin:bulletin, kb:kb);
 set_kb_item(name:"SMB/Missing/MS05-030", value:TRUE);
 hotfix_security_hole();
 }flag ++; }
	}

 if ( flag == 0 ) set_kb_item(name:"SMB/897715", value:TRUE);
}

NetUseDel();
