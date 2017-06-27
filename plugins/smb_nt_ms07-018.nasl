#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25026);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2016/01/28 22:37:17 $");

 script_cve_id("CVE-2007-0938", "CVE-2007-0939");
 script_bugtraq_id(22860, 22861);
 script_osvdb_id(34006, 34007);
 script_xref(name:"MSFT", value:"MS07-018");
 script_xref(name:"IAVB", value:"2007-B-0007");
 script_xref(name:"CERT", value:"434137");

 script_name(english:"MS07-018: Vulnerabilities in Microsoft Content Management Server Could Allow Remote Code Execution (925939)");
 script_summary(english:"Checks the remote file version for 925939");

 script_set_attribute(attribute:"synopsis", value:"A remote user can execute arbitrary code on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Microsoft Content Management
Server that is vulnerable to a security flaw that could allow a remote
user to execute arbitrary code by sending a specially malformed HTTP
request.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-018");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for MCMS SP1 and SP2.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/10");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/04/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:content_management_server");
 script_set_attribute(attribute:"stig_severity", value:"I");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS07-018';
kbs = make_list("924429", "924430");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_iis_installed() <= 0) audit(AUDIT_NOT_INST, "IIS");


rootfile = hotfix_get_programfilesdir();
if (!rootfile) exit(1, "Failed to get the Program Files directory.");

dll  =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Content Management Server\server\bin\AEServerObject.dll", string:rootfile);
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);

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

vuln = 0;

handle =  CreateFile (file:dll, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( !isnull(v) )
  {

   if (v[0] == 5 &&  v[1] == 0 && v[2] < 5317)
   {
     hotfix_add_report('\nPath : '+share-'$'+':'+dll+
                       '\nVersion : '+join(v, sep:'.')+
                      '\nShould be : 5.0.5317.0\n',
                      bulletin:bulletin,
                      kb:"924429");
     vuln++;
   }
   else if (v[0] == 4 &&  v[1] == 10 && v[2] < 1157)
   {
     hotfix_add_report('\nPath : '+share-'$'+':'+dll+
                       '\nVersion : '+join(v, sep:'.')+
                      '\nShould be : 4.10.1157.0\n',
                      bulletin:bulletin,
                      kb:"924430");
     vuln++;
   }
 }
}

NetUseDel();


if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
