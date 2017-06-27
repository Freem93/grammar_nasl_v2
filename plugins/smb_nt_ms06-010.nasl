#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(20910);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2016/06/30 19:55:38 $");

 script_cve_id("CVE-2006-0004");
 script_bugtraq_id(16634);
 script_osvdb_id(23135);
 script_xref(name:"MSFT", value:"MS06-010");

 script_name(english:"MS06-010: Vulnerability in PowerPoint 2000 Could Allow Information Disclosure (889167)");
 script_summary(english:"Determines the version of PowerPnt.exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote version of PowerPoint is vulnerable to an information
disclosure attack.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of PowerPoint that is vulnerable to
an information disclosure attack.

Specifically, an attacker could send a malformed PowerPoint file to a
a victim on the remote host. When the victim opens the file, the
attacker may be able to obtain access to the files in the Temporary
Internet Files Folder of the remote host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-010");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for PowerPoint.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/02/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/14");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");

 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("audit.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS06-010';
kb = '889167';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


path = get_kb_item_or_exit("SMB/Office/Powerpoint/9.0/Path");
share = hotfix_path2share(path:path);

ppt =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\PowerPnt.exe", string:path);


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

handle =  CreateFile (file:ppt, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if ( ! isnull(handle) )
{
 ppt_version = v =  GetFileVersion(handle:handle);
 CloseFile(handle:handle);
}


NetUseDel();

if ( ! isnull(ppt_version) )
{
 office_sp = get_kb_item("SMB/Office/2000/SP");
 if (!isnull(office_sp) && office_sp == 3)
 {
   if ( ppt_version[0] == 9 && ppt_version[1] == 0 && ppt_version[2] == 0 && ppt_version[3] < 8936)
	 {
     hotfix_add_report('\nPath : '+share-'$'+':'+ppt+
                       '\nVersion : '+join(v, sep:'.')+
                       '\nShould be : 9.0.0.8936\n',
                       bulletin:bulletin, kb:kb);
     set_kb_item(name:"SMB/Missing/MS06-010", value:TRUE);
     hotfix_security_warning();
   }
 }
}
audit(AUDIT_HOST_NOT, 'affected');
