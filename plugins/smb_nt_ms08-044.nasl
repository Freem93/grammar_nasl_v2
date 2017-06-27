#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(33873);
 script_version("$Revision: 1.31 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id(
  "CVE-2008-3018",
  "CVE-2008-3019",
  "CVE-2008-3020",
  "CVE-2008-3021",
  "CVE-2008-3460"
 );
 script_bugtraq_id(30595, 30597, 30598, 30599, 30600);
 script_osvdb_id(47397, 47398, 47400, 47401, 47402);
 script_xref(name:"MSFT", value:"MS08-044");


 script_name(english:"MS08-044: Vulnerabilities in Microsoft Office Filters Could Allow Remote Code Execution (924090)");
 script_summary(english:"Determines the version of some MS filters");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the
Microsoft Office filters.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of some Microsoft Office filters
that are subject to various flaws that could allow arbitrary code to
be run.

An attacker may use these to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it import it with Microsoft Office.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms08-044");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office 2000, XP and 2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(94, 399);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/08/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/08/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_converter_pack");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:works");
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

bulletin = 'MS08-044';
kbs = make_list("924090");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

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


kb       = '924090';
vuln = FALSE;
checkedfiles = make_array();
foreach ver (keys(office_versions))
{
  NetUseDel(close:FALSE);
  if (ver == "9.0" || ver == "10.0" || ver == "12.0")
  {
    if (typeof(rootfiles) == 'array') rootfile = rootfiles[ver];
    else rootfile = rootfiles;
    share = hotfix_path2share(path:rootfile);

    path = rootfile + "\Microsoft Shared\Grphflt\";
    dll1  =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Shared\Grphflt\Gifimp32.flt", string:rootfile);
    dll2 =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Shared\Grphflt\Gifimp32.flt_1033", string:rootfile);
    if (checkedfiles[dll1] || checkedfiles[dll2]) continue;

    r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if ( r != 1 ) continue;


    handle =  CreateFile (file:dll2, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
    if ( isnull(handle) )
    handle =  CreateFile (file:dll1, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

    if ( ! isnull(handle) )
    {
      checkedfiles[dll1] = 1;
      checkedfiles[dll2] = 1;
      v = GetFileVersion(handle:handle);
      CloseFile(handle:handle);
      if ( !isnull(v) )
      {
        # v < 2003.1100.8165.0  => vulnerable
        if (( v[0] == 2003 &&  v[1] == 1100 && v[2] < 8165)  ||
           (  v[0] == 2003 &&  v[1] < 1100 ) ||
           (  v[0] < 2003 ))
        {
          vuln = TRUE;
          info =
            'Path              : ' + path + '\n' +
            'Installed version : ' + join(v, sep:'.') + '\n' +
            'Fix               : 2003.100.8165.0 \n';
          hotfix_add_report(info, bulletin:bulletin, kb:kb);
        }
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
