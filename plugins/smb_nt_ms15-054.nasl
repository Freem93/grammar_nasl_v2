#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83363);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/06/13 18:17:11 $");

  script_cve_id("CVE-2015-1681");
  script_bugtraq_id(74486);
  script_osvdb_id(122018);
  script_xref(name:"MSFT", value:"MS15-054");

  script_name(english:"MS15-054: Vulnerability in Microsoft Management Console File Format Could Allow Denial of Service (3051768)");
  script_summary(english:"Checks the version of comctl32.dll.");

  script_set_attribute(attribute:"synopsis",value:
"The remote Windows host is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description",value:
"The remote Windows host is affected by a flaw due to a failure to
properly validate a destination buffer when retrieving icon
information from a specially crafted Microsoft Management Console
(.msc) file. An unauthenticated, remote attacker, by tricking a victim
into opening a malicious .msc file, can exploit this flaw to cause a
denial of service.");
  script_set_attribute(attribute:"see_also",value:"http://www.zerodayinitiative.com/advisories/ZDI-15-191/");
  script_set_attribute(attribute:"see_also",value:"https://technet.microsoft.com/en-us/library/security/ms15-054");
  script_set_attribute(attribute:"solution",value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, 2012, 8.1, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date",value:"2015/05/12");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS15-054';
kb = '3051768';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

systemroot = hotfix_get_systemroot();
if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();

if (!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

winsxs = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\WinSxS", string:systemroot);
winsxs_share = hotfix_path2share(path:systemroot);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:winsxs_share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, winsxs_share);
}

files = list_dir(basedir:winsxs, level:0, dir_pat:"microsoft.windows.common-controls", file_pat:"^comctl32\.dll$", max_recurse:1);

if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_check_winsxs(os:'6.3', 
                      sp:0, 
                      files:files, 
                      versions:make_list('6.10.9600.17784'), 
                      max_versions:make_list('6.10.9600.99999'), 
                      bulletin:bulletin, 
                      kb:kb) ||

  # Windows 8 64bit / Windows Server 2012
  hotfix_check_winsxs(os:'6.2', 
                      sp:0, 
                      files:files, 
                      versions:make_list('6.10.9200.21435','6.10.9200.17321'), 
                      max_versions:make_list('6.10.9200.99999','6.10.9200.19999'), 
                      bulletin:bulletin, 
                      kb:kb) ||

  # Windows 7 SP1 / Server 2008 R2
  hotfix_check_winsxs(os:'6.1', 
                      sp:1, 
                      files:files, 
                      versions:make_list('6.10.7601.23011','6.10.7601.18807'), 
                      max_versions:make_list('6.10.7601.99999','6.10.7601.20000'), 
                      bulletin:bulletin, 
                      kb:kb) ||

  # Windows Vista / Server 2008
  hotfix_check_winsxs(os:'6.0', 
                      sp:2, 
                      files:files, 
                      versions:make_list('6.10.6002.23663','6.10.6002.19355'), 
                      max_versions:make_list('6.10.6002.99999','6.10.6002.20000'), 
                      bulletin:bulletin, 
                      kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  NetUseDel();
  exit(0);
}
else
{
  NetUseDel();
  audit(AUDIT_HOST_NOT, 'affected');
}
