#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(31416);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2016/06/30 19:55:38 $");

 script_cve_id("CVE-2006-4695", "CVE-2007-1201");
 script_bugtraq_id(28135, 28136);
 script_osvdb_id(42711, 42712);
 script_xref(name:"CERT", value:"654577");
 script_xref(name:"MSFT", value:"MS08-017");

 script_name(english:"MS08-017: Vulnerabilities in Microsoft Office Web Components Could Allow Remote Code Execution (933103)");
 script_summary(english:"Determines the version of MSO.dll");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Office Web Components.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Office Web
Components that is subject to various flaws that could allow arbitrary
code to be run.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send specially crafted URLS to
a user of the remote computer and have it process it with Microsoft
Office Web Components.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS08-017");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office 2000, XP and 2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
 script_cwe_id(94);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/11");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/03/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:biztalk_server");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_.net");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:commerce_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

bulletin = 'MS08-017';
kbs = make_list("933103");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

office_versions = hotfix_check_office_version ();
if ( !office_versions ) exit(0, "Microsoft Office not found.");

rootfiles = hotfix_get_officeprogramfilesdir();
if ( ! rootfiles ) exit(1, "Failed to get Office Program Files directory.");

login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");


share = '';
lastshare = '';
kb       = '933103';
foreach ver (keys(office_versions))
{
  if (typeof(rootfiles) == 'array') rootfile = rootfiles[ver];
  else rootfile = rootfiles;
  if ( "9.0" >< ver )
  {
    dll  =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Office\Office\msowc.dll", string:rootfile);
    path = rootfile + "\Microsoft Office\Office\";
  }
  else if ( "10.0" >< ver )
  {
    dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Office\Office10\msowc.dll", string:rootfile);
    path = rootfile + "\Microsoft Office\Office10\";
  }
  else continue;
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
      if ( ( v[0] == 9 &&  v[1] == 0 && v[2] == 0 && v[3] < 8966 )  )
      {
        set_kb_item(name:"SMB/Missing/MS08-017", value:TRUE);
        info =
          'Product           : Office Web Component ' + '\n' +
          'Path              : ' + path + '\n' +
          'Installed version : ' + join(v, sep:'.') + '\n' +
          'Fix               : 9.0.0.8966 \n';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
        NetUseDel();
        hotfix_security_hole();
        exit(0);
      }
    }
  }
}
NetUseDel();
audit(AUDIT_HOST_NOT, 'affected');
