#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22189);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2016/06/30 19:55:38 $");

 script_cve_id("CVE-2006-3649");
 script_bugtraq_id(19414);
 script_osvdb_id(27849);
 script_xref(name:"CERT", value:"159484");
 script_xref(name:"MSFT", value:"MS06-047");

 script_name(english:"MS06-047: Vulnerability in Microsoft Visual Basic for Applications Could Allow Remote Code Execution (921645)");
 script_summary(english:"Determines the version of vbe6.dll");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host through VBA.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Visual Basic for
Applications that is vulnerable to a buffer overflow when handling
malformed documents.

An attacker may exploit this flaw to execute arbitrary code on this
host by sending a malformed file to a user of the remote host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-047");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/08/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/08");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:access");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:works");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_basic_software_development_kit");
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

bulletin = 'MS06-047';
kb = '921645';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


common = hotfix_get_commonfilesdir();
if ( ! common ) exit(1, "Failed to get the Common Files directory.");



#VBA 6- C:\Program Files\Common Files\Microsoft Shared\VBA\VBA6\vbe6.dll = 6.4.99.72
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:common);
vba6 =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Shared\VBA\VBA6\vbe6.dll", string:common);

port = kb_smb_transport();
if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

r = NetUseAdd(login:kb_smb_login(), password:kb_smb_password(), domain:kb_smb_domain(), share:share);
if ( r != 1 )
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

handle = CreateFile (file:vba6, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) )
 {
 if ( v[0] == 6 && ( v[1] < 4 || ( v[1] == 4 && v[2] < 99 ) || ( v[1] == 4 && v[2] == 99 && v[3] < 72 ) ) )
	{
	 {
 hotfix_add_report('\nPath : '+share-'$'+':'+vba6+
                   '\nVersion : '+join(v, sep:'.')+
                   '\nShould be : 6.4.99.72\n',
                   bulletin:bulletin, kb:kb);
 set_kb_item(name:"SMB/Missing/MS06-047", value:TRUE);
 hotfix_security_warning();
 }
	NetUseDel();
	exit(0);
	}
 }
 else
 {
  NetUseDel();
  exit(1, "Failed to get file version.");
 }
}


NetUseDel();
