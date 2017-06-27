#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(31415);
 script_version("$Revision: 1.42 $");
 script_cvs_date("$Date: 2017/04/03 14:49:09 $");
 script_cve_id("CVE-2007-1747", "CVE-2008-0113", "CVE-2008-0118");
 script_bugtraq_id(23826, 28146);
 script_osvdb_id(34396, 42708, 42709);
 script_xref(name:"CERT", value:"853184");
 script_xref(name:"MSFT", value:"MS08-016");


 script_name(english:"MS08-016: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (949030)");
 script_summary(english:"Determines the version of MSO.dll");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Office.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Office that is
subject to various flaws that could allow arbitrary code to be run.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it with Microsoft Office.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS08-016");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office 2000, XP and 2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_cwe_id(94, 399);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/03/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS08-016';
kbs = make_list("947355", "947361", "947866");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

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

foreach ver (keys(office_versions))
{
  info = NULL;
  if (typeof(rootfiles) == 'array') rootfiles = rootfiles[ver];
  else rootfile = rootfiles;
  if ( "9.0" >< ver )
  {
    rootfile = hotfix_get_officeprogramfilesdir(officever:'9.0');
    dll  =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Office\Office\mso9.dll", string:rootfile);
    path = rootfile + "\Microsoft Office\Office\";
  }
  else if ( "10.0" >< ver )
  {
    dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Shared\Office10\mso.dll", string:rootfile);
    path = rootfile + "\Microsoft Shared\Office10\";
  }
  else if ( "11.0" >< ver )
  {
    dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Shared\Office11\mso.dll", string:rootfile);
    path = rootfile + "\Microsoft Shared\Office11\";
  }

  share = hotfix_path2share(path:rootfile);
  if (share != lastshare)
  {
    NetUseDel(close:FALSE);
    r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if ( r != 1 ) audit(AUDIT_SHARE_FAIL, share);
  }

  handle =  CreateFile (file:dll, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

  if ( ! isnull(handle) )
  {
    v = GetFileVersion(handle:handle);
    CloseFile(handle:handle);
    if ( !isnull(v) )
    {
      version = join(v, sep:'.');
      if (v[0] == 9 && v[1] == 0 && v[2] == 0 && v[3] < 8968)
      {
        vuln = TRUE;
        info =
          'Product           : Microsoft Office 2000\n' +
          'Path              : ' + path + '\n' +
          'Installed version : ' + version + '\n' +
          'Fix               : 9.0.0.8968';
        kb = '947361';
      }
      else if (v[0] == 10 && v[1] == 0 && v[2] < 6839)
      {
        vuln = TRUE;
        info =
          'Product           : Microsoft Office 2002\n' +
          'Path              : ' + path + '\n' +
          'Installed version : ' + version + '\n' +
          'Fix               : 10.0.6839.0';
        kb = '947866';
      }
      else if (v[0] == 11 && v[1] == 0 && v[2] < 8172)
      {
        vuln = TRUE;
        info =
          'Product           : Microsoft Office 2003\n' +
          'Path              : ' + path + '\n' +
          'Installed version : ' + version + '\n' +
          'Fix               : 11.0.8172.0';
        kb = '947355';
      }
    }
    if (info)
    {
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
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
