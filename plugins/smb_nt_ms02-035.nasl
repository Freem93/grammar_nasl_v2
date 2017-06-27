#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11322);
 script_version("$Revision: 1.43 $");
 script_cvs_date("$Date: 2017/05/26 15:15:35 $");

 script_cve_id("CVE-2002-0643");
 script_bugtraq_id(5203);
 script_osvdb_id(10141);
 script_xref(name:"CERT", value:"338195");
 script_xref(name:"MSFT", value:"MS02-035");
 script_xref(name:"MSKB", value:"263968");

 script_name(english:"MS02-035: MS SQL Installation may leave passwords on system (263968)");
 script_summary(english:"Reads %windir%\setup.iss");

 script_set_attribute(attribute:"synopsis", value:
"It may be possible to get the remote SQL Server's administrator
password.");
 script_set_attribute(attribute:"description", value:
"The installation process for the remote MS SQL Server left files named
'setup.iss' on the remote host. These files contain the password
assigned to the 'sa' account of the remote database.

An attacker who manages to view these files may be able to leverage
this issue to gain full administrative access to the application.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms02-035");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for SQL Server 7 and 2000.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/07/10");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/07/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/06");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
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

bulletin = 'MS02-035';
kb = '263968';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);



rootfile = hotfix_get_systemroot();
if ( ! rootfile ) exit(1, "Failed to get system root.");

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
rootfile =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\setup.iss", string:rootfile);


port    = kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

r = NetUseAdd(login:kb_smb_login(), password:kb_smb_password(), domain:kb_smb_domain(), share:share);
if ( r != 1 )
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

foreach file (make_list("MSSQL7\Install\setup.iss", rootfile))
{
 handle =  CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

 if ( ! isnull(handle) )
 {
  resp = ReadFile(handle:handle, length:16384, offset:0);
  CloseFile(handle:handle);
  if("svPassword=" >< resp){
	 {
 set_kb_item(name:"SMB/Missing/MS02-035", value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_warning();
 }
	NetUseDel();
	exit(0);
	}
 }
}

NetUseDel();


