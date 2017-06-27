#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22033);
 script_version("$Revision: 1.33 $");
 script_cvs_date("$Date: 2016/07/07 15:05:40 $");

 script_cve_id("CVE-2006-0033", "CVE-2006-0007");
 script_bugtraq_id(18915, 18913);
 script_osvdb_id(27146, 27147);
 script_xref(name:"CERT", value:"459388");
 script_xref(name:"CERT", value:"668564");
 script_xref(name:"MSFT", value:"MS06-039");

 script_name(english:"MS06-039: Vulnerabilities in Microsoft Office Filters Could Allow Remote Code Execution (915384)");
 script_summary(english:"Determines the version of some MS filters");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the
Microsoft Office filters.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of some Microsoft Office filters
that are subject to various flaws which could allow arbitrary code to
be run.

An attacker could use these to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it import it with Microsoft Office.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-039");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office 2000, XP and 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/11");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/07/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:frontpage");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:onenote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:works");
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

bulletin = 'MS06-039';
kb = '915384';

kbs = make_list(kb);
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

share = '';
lastshare = '';
vuln = FALSE;
checkedfiles = make_array();
foreach ver (keys(office_versions))
{
  if (ver == "9.0" || ver == "10.0" || ver == "11.0")
  {
    if (typeof(rootfiles) == 'array') rootfile = rootfiles[ver];
    else rootfile = rootfiles;
    share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);

    dll1  =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Shared\Grphflt\Gifimp32.flt", string:rootfile);
    dll2 =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Shared\Grphflt\Gifimp32.flt_1033", string:rootfile);
    if(checkedfiles[dll1] || checkedfiles[dll2]) continue;

    share = hotfix_path2share(path:rootfile);
    if (share != lastshare)
    {
      NetUseDel(close:FALSE);
      r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
      if ( r != 1 ) audit(AUDIT_SHARE_FAIL,share);

      handle =  CreateFile (file:dll2, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
      dll = dll2;
      if ( isnull(handle) )
      {
        dll = dll1;
        handle =  CreateFile (file:dll1, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
      }

      if ( ! isnull(handle) )
      {
        checkedfiles[dll1] = 1;
        checkedfiles[dll2] = 1;
        v = GetFileVersion(handle:handle);
        CloseFile(handle:handle);
        if ( !isnull(v) )
        {
          # v < 2003.1100.8020.0 => vulnerable
          if ( ( v[0] == 2003 &&  v[1] == 1100 && v[2] < 8020)  ||
	           ( v[0] == 2003 &&  v[1] < 1100 ) ||
	           ( v[0] < 2003 ) )
          {
            vuln = TRUE;
            hotfix_add_report('\nPath : '+share-'$'+':'+dll+
                              '\nVersion : '+join(v, sep:'.')+
                              '\nShould be : 2003.1100.8020.0\n',
                              bulletin:bulletin, kb:kb);
            break;
          }
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
else
{
  audit(AUDIT_HOST_NOT, 'affected');
}
