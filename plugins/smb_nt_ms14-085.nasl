#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79834);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id("CVE-2014-6355");
  script_bugtraq_id(71502);
  script_osvdb_id(113201);
  script_xref(name:"MSFT", value:"MS14-085");

  script_name(english:"MS14-085: Vulnerability in Microsoft Graphics Component Could Allow Information Disclosure (3013126)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Microsoft Graphics Component installed on the
remote host is affected by an information disclosure vulnerability due
to the way JPEG content is decoded. A remote attacker can exploit this
vulnerability by convincing a user to browse to a website containing
specially crafted JPEG content, resulting in the disclosure of
information that can aid in further attacks.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-085");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Server 2003,
Vista, Server 2008, 7, Server 2008 R2, 8, 8.1, Server 2012, and Server
2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS14-085';
kb  = "3013126";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
# Some of the 2k3 checks could flag XP 64, which is unsupported
if ("Windows XP" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

systemroot = hotfix_get_systemroot();
if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

vuln = 0;

if ("2003" >!< productname)
{
  if (
    # Windows 8.1 / Windows Server 2012 R2
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"WindowsCodecs.dll", version:"6.3.9600.17483", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

    # Windows 8 / Windows Server 2012
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"WindowsCodecs.dll", version:"6.2.9200.21283", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"WindowsCodecs.dll", version:"6.2.9200.17170", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

    # Windows 7 / Server 2008 R2
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"WindowsCodecs.dll", version:"6.2.9200.21283", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"WindowsCodecs.dll", version:"6.2.9200.17170", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"WindowsCodecs.dll", version:"6.1.7601.22865", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"WindowsCodecs.dll", version:"6.1.7601.18658", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

    # Vista / Windows Server 2008
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"WindowsCodecs.dll", version:"7.0.6002.23535", min_version:"7.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"WindowsCodecs.dll", version:"7.0.6002.19227", min_version:"7.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb)
  )
  vuln++;
}
else
{
  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();

  # GDI+ Check
  winsxs = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\WinSxS", string:systemroot);
  winsxs_share = hotfix_path2share(path:systemroot);

  if ( hcf_init == 0 ) hotfix_check_fversion_init();
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:winsxs_share);
  if (rc != 1)
    NetUseDel(close:FALSE);
  else
  {
    ###########################
    # GDI+ check
    ###########################
    files = list_dir(basedir:winsxs, level:0, dir_pat:"microsoft.windows.gdiplus", file_pat:"^gdiplus\.dll$", max_recurse:1);
    # Windows Server 2003
    vuln += hotfix_check_winsxs(os:'5.2', sp:2, files:files, versions:make_list('5.2.6002.23535'), max_versions:make_list('5.2.6002.99999'), bulletin:bulletin, kb:kb);
  }
}

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
