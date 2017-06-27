#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(16332);
 script_version("$Revision: 1.35 $");
 script_cvs_date("$Date: 2016/07/11 14:12:52 $");

 script_cve_id("CVE-2004-0848");
 script_bugtraq_id(12480);
 script_osvdb_id(13594);
 script_xref(name:"MSFT", value:"MS05-005");
 script_xref(name:"CERT", value:"416001");

 script_name(english:"MS05-005: Vulnerability in Microsoft Office XP could allow Remote Code Execution (873352)");
 script_summary(english:"Determines the version of MSO.dll");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the Office
client.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Office that could
allow an attacker to execute arbitrary code on the remote host.

To exploit this flaw, an attacker would need to send a specially
crafted file to a user on the remote host and wait for him to open it
using Microsoft Office.

When opening the malformed file, Microsoft Office will encounter a
buffer overflow which may be exploited to execute arbitrary code.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms05-005");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office XP.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/02/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/09");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:works");
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

bulletin = 'MS05-005';
kbs = make_list("873352", "873354", "873355");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

office_versions = hotfix_check_office_version ();
project_versions = get_kb_list("SMB/Office/Project/*/ProductPath");
visio_versions = get_kb_list("SMB/Office/Visio/*/VisioPath");
works_version = get_kb_item("SMB/Works/Version");

if (!office_version || (office_version >!< "10.0"))
{
  if (!hotfix_check_works_installed ()) exit (0);

  if (!works_version || (works_version != "6.0" && works_version != "7.0"))
    exit (0);
}


kb = "";
if (!isnull(office_versions) && office_versions["10.0"]) kb = "873352";
else if (!isnull(project_versions))
{
  foreach version (keys(project_versions))
  {
    if ('10.0' >< version)
    {
      kb = "873355";
      break;
    }
  }
}
else if (!isnull(visio_versions))
{
  foreach version (keys(visio_versions))
  {
    if ('10.0' >< version)
    {
      kb = "873354";
      break;
    }
  }
}
else if (works_version) kb = "873352";


rootfile = hotfix_get_commonfilesdir();
if ( ! rootfile ) exit(1, "Failed to get the Common Files directory.");

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Shared\Office10\mso.dll", string:rootfile);


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
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( v[0] == 10 &&  v[1] ==  0 && v[2] < 6735  )
	 {
 report = '\nFile : mso.dll\nVersion : '+join(v, sep:'.')+'\nFixed version : 10.0.6735.0\n';
 hotfix_add_report(report, bulletin:bulletin, kb:kb);
 set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
 hotfix_security_hole();
 NetUseDel();
 exit(0);
 }
}

NetUseDel();
audit(AUDIT_HOST_NOT, 'affected');
